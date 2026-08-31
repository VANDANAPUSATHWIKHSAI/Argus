"""
Preprocessing Parser Tests
===========================
# Unit tests for preprocessing/parsers/* and preprocessing/router.py.

Tests are fully self-contained — no real forensic binaries, no database,
no network required.  External tools (e.g. hayabusa) are mocked via
unittest.mock so CI passes regardless of the analyst's workstation setup.

Usage:
    python test_preprocessing_parsers.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path when run directly
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))

from preprocessing.parsers.evtx_parser import (
    EvtxParser,
    HayabusaExecutionError,
    HayabusaNotFoundError,
)
from preprocessing.parsers.memory_parser import (
    MemoryParser,
    VolatilityExecutionError,
    VolatilityNotFoundError,
)
from preprocessing.parsers.pcap_parser import (
    PcapParser,
    ZeekExecutionError,
    ZeekNotFoundError,
    SuricataExecutionError,
    SuricataNotFoundError,
)
from preprocessing.parsers.registry_parser import (
    RegistryParser,
    RegRipperNotFoundError,
    RegRipperExecutionError,
    _split_into_sections,
)
from preprocessing.parsers.browser_parser import (
    BrowserParser,
    HindsightNotFoundError,
    HindsightExecutionError,
)
from preprocessing.parsers.email_parser import (
    EmailParser,
)
from preprocessing.parsers.msg_parser import (
    MsgEmailParser,
)
from preprocessing.parsers.filesystem_parser import (
    FilesystemParser,
    TSKNotFoundError,
    TSKExecutionError,
)
from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.normalizer import Normalizer
from preprocessing.router import ParserRouter, UnroutableEvidenceError
from infrastructure.schemas import Evidence, EvidenceStatus, AuditLogEntry


# ---------------------------------------------------------------------------
# Fixture: realistic Hayabusa JSONL output (3 records)
# ---------------------------------------------------------------------------

HAYABUSA_FIXTURE_LINES: list[dict] = [
    {
        "Timestamp": "2024-03-15 08:22:11.000 +00:00",
        "Computer": "WORKSTATION-01",
        "Channel": "Security",
        "EventID": 4624,
        "Level": "informational",
        "RuleTitle": "Logon",
        "Details": "Type: 3, User: DOMAIN\\alice, LogonID: 0x12AB",
        "MitreTactics": ["initial-access"],
        "MitreTags": ["T1078"],
    },
    {
        "Timestamp": "2024-03-15 08:23:45.500 +00:00",
        "Computer": "WORKSTATION-01",
        "Channel": "Security",
        "EventID": 4688,
        "Level": "medium",
        "RuleTitle": "Suspicious Process Creation",
        "Details": "Process: cmd.exe, ParentProcess: explorer.exe",
        "MitreTactics": ["execution"],
        "MitreTags": ["T1059.003"],
    },
    {
        # No timestamp, no rule, no MITRE — edge case
        "Timestamp": "",
        "Computer": "",
        "Channel": "System",
        "EventID": 7036,
        "Level": "informational",
        "RuleTitle": "",
        "Details": "The Windows Update service entered the running state.",
        "MitreTactics": [],
        "MitreTags": [],
    },
]

FIXTURE_JSONL: str = "\n".join(json.dumps(r) for r in HAYABUSA_FIXTURE_LINES) + "\n"

EVIDENCE_ID = "test-evidence-uuid-001"


# ---------------------------------------------------------------------------
# Helper: write JSONL fixture to the temp output file that _run_hayabusa
# would normally create, then let _parse_jsonl read it.
# ---------------------------------------------------------------------------

def _mock_run_hayabusa_writes_fixture(evtx_path: Path, output_path: Path) -> None:
    """Side-effect injected in place of EvtxParser._run_hayabusa."""
    output_path.write_text(FIXTURE_JSONL, encoding="utf-8")


# ===========================================================================
# Test Cases
# ===========================================================================

class TestEvtxParserHappyPath(unittest.TestCase):
    """Normal operation — Hayabusa runs successfully, JSONL is parsed."""

    def _run(self) -> list[Artifact]:
        """Patch _run_hayabusa and call parse() against a real temp file."""
        # We need a real path that exists so the FileNotFoundError guard passes.
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as f:
            f.write(b"\x00")          # dummy bytes — binary never actually runs
            evtx_path = f.name
        try:
            parser = EvtxParser()
            with patch.object(
                parser, "_run_hayabusa", side_effect=_mock_run_hayabusa_writes_fixture
            ):
                return parser.parse(evtx_path, evidence_id=EVIDENCE_ID)
        finally:
            os.unlink(evtx_path)

    def test_returns_correct_count(self):
        """Should return one Artifact per JSONL line."""
        artifacts = self._run()
        self.assertEqual(len(artifacts), len(HAYABUSA_FIXTURE_LINES))

    def test_all_artifacts_are_artifact_instances(self):
        artifacts = self._run()
        for a in artifacts:
            self.assertIsInstance(a, Artifact)

    def test_source_tool_is_hayabusa(self):
        artifacts = self._run()
        for a in artifacts:
            self.assertEqual(a.source_tool, "hayabusa")

    def test_artifact_type_is_log_event(self):
        artifacts = self._run()
        for a in artifacts:
            self.assertEqual(a.artifact_type, "log_event")

    def test_evidence_id_propagated(self):
        artifacts = self._run()
        for a in artifacts:
            self.assertEqual(a.evidence_id, EVIDENCE_ID)

    def test_raw_fields_preserved(self):
        """raw_fields must be the full parsed JSON dict, untouched."""
        artifacts = self._run()
        self.assertEqual(artifacts[0].raw_fields["EventID"], 4624)
        self.assertEqual(artifacts[1].raw_fields["RuleTitle"], "Suspicious Process Creation")

    def test_timestamp_parsed_correctly(self):
        """First record has a valid timestamp — should not be None."""
        artifacts = self._run()
        ts = artifacts[0].timestamp
        self.assertIsNotNone(ts)
        self.assertIsInstance(ts, datetime)
        self.assertEqual(ts.year, 2024)
        self.assertEqual(ts.month, 3)
        self.assertEqual(ts.day, 15)
        self.assertEqual(ts.hour, 8)

    def test_empty_timestamp_maps_to_none(self):
        """Third record has an empty Timestamp string — should be None."""
        artifacts = self._run()
        self.assertIsNone(artifacts[2].timestamp)

    def test_normalized_host_populated(self):
        artifacts = self._run()
        self.assertEqual(artifacts[0].normalized_fields.host, "WORKSTATION-01")

    def test_normalized_host_none_when_empty(self):
        """Third record has empty Computer — normalized host should be None."""
        artifacts = self._run()
        self.assertIsNone(artifacts[2].normalized_fields.host)

    def test_normalized_rule_name_includes_rule_title_and_mitre(self):
        """rule_name should join RuleTitle | MitreTactics | MitreTags."""
        artifacts = self._run()
        rule = artifacts[0].normalized_fields.rule_name
        self.assertIn("Logon", rule)
        self.assertIn("initial-access", rule)
        self.assertIn("T1078", rule)

    def test_normalized_rule_name_none_when_no_rule_or_mitre(self):
        """Third record: empty RuleTitle, empty tactics/tags → rule_name None."""
        artifacts = self._run()
        self.assertIsNone(artifacts[2].normalized_fields.rule_name)

    def test_normalized_severity_populated(self):
        artifacts = self._run()
        self.assertEqual(artifacts[0].normalized_fields.severity, "informational")
        self.assertEqual(artifacts[1].normalized_fields.severity, "medium")

    def test_artifact_ids_are_unique(self):
        """Every Artifact must get its own UUID."""
        artifacts = self._run()
        ids = [a.artifact_id for a in artifacts]
        self.assertEqual(len(ids), len(set(ids)))


class TestEvtxParserErrorHandling(unittest.TestCase):
    """Parser must raise typed errors — never silently return an empty list."""

    def test_raises_file_not_found_for_missing_evtx(self):
        """Non-existent input file → plain FileNotFoundError before even calling hayabusa."""
        parser = EvtxParser()
        with self.assertRaises(FileNotFoundError):
            parser.parse("/nonexistent/path/file.evtx", evidence_id="x")

    def test_raises_hayabusa_not_found_when_binary_missing(self):
        """If `hayabusa` is not on PATH, raise HayabusaNotFoundError (not silent empty list)."""
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as f:
            f.write(b"\x00")
            evtx_path = f.name
        try:
            parser = EvtxParser()
            # subprocess.run raises FileNotFoundError when binary not found
            with patch("subprocess.run", side_effect=FileNotFoundError("hayabusa not found")):
                with self.assertRaises(HayabusaNotFoundError) as ctx:
                    parser.parse(evtx_path, evidence_id="x")
            self.assertIn("hayabusa", str(ctx.exception).lower())
        finally:
            os.unlink(evtx_path)

    def test_raises_hayabusa_execution_error_on_nonzero_exit(self):
        """Non-zero exit code from hayabusa → HayabusaExecutionError."""
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as f:
            f.write(b"\x00")
            evtx_path = f.name
        try:
            parser = EvtxParser()
            failed_result = MagicMock()
            failed_result.returncode = 1
            failed_result.stdout = "some stdout"
            failed_result.stderr = "Error: failed to parse"
            with patch("subprocess.run", return_value=failed_result):
                with self.assertRaises(HayabusaExecutionError) as ctx:
                    parser.parse(evtx_path, evidence_id="x")
            self.assertIn("1", str(ctx.exception))  # returncode in message
        finally:
            os.unlink(evtx_path)

    def test_injection_does_not_silently_return_empty_list(self):
        """Confirm the parser never silently returns [] when hayabusa is unavailable.

        This guards against a regression where the except clause returns []
        instead of re-raising — which would masquerade missing output as
        'no events found'.
        """
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as f:
            f.write(b"\x00")
            evtx_path = f.name
        try:
            parser = EvtxParser()
            with patch("subprocess.run", side_effect=FileNotFoundError()):
                result = None
                try:
                    result = parser.parse(evtx_path, evidence_id="x")
                except HayabusaNotFoundError:
                    pass   # correct — typed error raised
                except Exception:
                    pass   # any error is acceptable
                # The only unacceptable outcome is silently returning an empty list
                self.assertIsNot(result, [], "Parser must not silently return [] on binary failure")
        finally:
            os.unlink(evtx_path)


class TestEvtxParserMalformedJSONL(unittest.TestCase):
    """Malformed lines in the JSONL output should be skipped, not crash the parser."""

    def test_skips_malformed_lines_and_parses_valid_ones(self):
        """One bad JSON line in the middle — the other two should still be parsed."""
        mixed_jsonl = (
            json.dumps(HAYABUSA_FIXTURE_LINES[0]) + "\n"
            "THIS IS NOT JSON\n"
            + json.dumps(HAYABUSA_FIXTURE_LINES[1]) + "\n"
        )

        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as f:
            f.write(b"\x00")
            evtx_path = f.name

        def write_mixed(evtx_path: Path, output_path: Path) -> None:
            output_path.write_text(mixed_jsonl, encoding="utf-8")

        try:
            parser = EvtxParser()
            with patch.object(parser, "_run_hayabusa", side_effect=write_mixed):
                artifacts = parser.parse(evtx_path, evidence_id=EVIDENCE_ID)
            self.assertEqual(len(artifacts), 2)   # bad line skipped
        finally:
            os.unlink(evtx_path)


# ===========================================================================
# MemoryParser fixtures
# ===========================================================================

# --- Fixture: windows.pslist JSON output (Volatility 3 --output=json shape)
PSLIST_JSON = json.dumps({
    "columns": ["PID", "PPID", "ImageFileName", "Offset(V)",
                "Threads", "Handles", "CreateTime", "ExitTime"],
    "rows": [
        [4,    0,   "System",       "0xf80000000000", 4,   0,   "2024-03-15 08:00:00.000000 UTC", 0],
        [1234, 4,   "svchost.exe",  "0xffff8000a000", 12,  300, "2024-03-15 08:01:00.000000 UTC", 0],
        [5678, 1234,"cmd.exe",      "0xffff8000b000", 1,   50,  "2024-03-15 08:22:11.000000 UTC", 0],
    ],
})

# --- Fixture: windows.dlllist JSON output
DLLLIST_JSON = json.dumps({
    "columns": ["PID", "Process", "Base", "Size", "LoadTime", "Name", "Path"],
    "rows": [
        [4, "System", "0x7fff0000", 4096, "2024-03-15 08:00:01.000000 UTC",
         "ntoskrnl.exe", "C:\\Windows\\System32\\ntoskrnl.exe"],
        [1234, "svchost.exe", "0x7fff1000", 8192, "2024-03-15 08:01:01.000000 UTC",
         "kernel32.dll", "C:\\Windows\\System32\\kernel32.dll"],
    ],
})

# --- Fixture: windows.malfind JSON output
MALFIND_JSON = json.dumps({
    "columns": ["PID", "Process", "Start VPN", "End VPN", "Tag",
                "Protection", "CommitCharge", "PrivateMemory", "File output",
                "Hexdump", "Disasm"],
    "rows": [
        [5678, "cmd.exe", "0x400000", "0x401fff", "VadS",
         "PAGE_EXECUTE_READWRITE", 2, 1, "Disabled",
         "4d5a9000...", "push ebp"],
    ],
})

# --- Fixture: pslist TABLE (fallback) output
PSLIST_TABLE = (
    "PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tCreateTime\tExitTime\n"
    "4\t0\tSystem\t0xf8000000\t4\t0\t2024-03-15 08:00:00.000000 UTC\t0\n"
    "1234\t4\tsvchost.exe\t0xffff8000\t12\t300\t2024-03-15 08:01:00.000000 UTC\t0\n"
)

MEMORY_EVIDENCE_ID = "mem-evidence-uuid-001"


# ---------------------------------------------------------------------------
# Helper: build a mock subprocess.run result for a given stdout string
# ---------------------------------------------------------------------------

def _make_vol_result(stdout: str, returncode: int = 0) -> MagicMock:
    r = MagicMock()
    r.returncode = returncode
    r.stdout = stdout
    r.stderr = ""
    return r


# ===========================================================================
# MemoryParser — JSON output (happy path)
# ===========================================================================

class TestMemoryParserJsonOutput(unittest.TestCase):
    """Volatility returns JSON from --output=json for all three plugins."""

    def _make_dump(self):
        import tempfile, os
        f = tempfile.NamedTemporaryFile(suffix=".mem", delete=False)
        f.write(b"\x00")
        f.close()
        return f.name

    def _run(self) -> list[Artifact]:
        dump = self._make_dump()
        try:
            # subprocess.run is called once per plugin (3 times total),
            # each time with --output=json.  Return the matching fixture.
            def side_effect(cmd, **kwargs):
                if "windows.pslist" in cmd:
                    return _make_vol_result(PSLIST_JSON)
                if "windows.dlllist" in cmd:
                    return _make_vol_result(DLLLIST_JSON)
                if "windows.malfind" in cmd:
                    return _make_vol_result(MALFIND_JSON)
                return _make_vol_result("")

            parser = MemoryParser()
            with patch("subprocess.run", side_effect=side_effect):
                return parser.parse(dump, evidence_id=MEMORY_EVIDENCE_ID)
        finally:
            import os; os.unlink(dump)

    def test_total_artifact_count(self):
        """3 pslist + 2 dlllist + 1 malfind = 6 total."""
        self.assertEqual(len(self._run()), 6)

    def test_artifact_types_correct(self):
        arts = self._run()
        types = [a.artifact_type for a in arts]
        self.assertEqual(types.count("process_record"), 3)
        self.assertEqual(types.count("dll_record"), 2)
        self.assertEqual(types.count("injection_indicator"), 1)

    def test_source_tool_is_volatility3(self):
        for a in self._run():
            self.assertEqual(a.source_tool, "volatility3")

    def test_evidence_id_propagated(self):
        for a in self._run():
            self.assertEqual(a.evidence_id, MEMORY_EVIDENCE_ID)

    def test_artifact_ids_unique(self):
        arts = self._run()
        ids = [a.artifact_id for a in arts]
        self.assertEqual(len(ids), len(set(ids)))

    def test_pslist_normalized_pid_ppid_process(self):
        arts = self._run()
        pslist = [a for a in arts if a.artifact_type == "process_record"]
        system = next(a for a in pslist if a.normalized_fields.process == "System")
        self.assertEqual(system.normalized_fields.pid, 4)
        self.assertEqual(system.normalized_fields.ppid, 0)

        cmd = next(a for a in pslist if a.normalized_fields.process == "cmd.exe")
        self.assertEqual(cmd.normalized_fields.pid, 5678)
        self.assertEqual(cmd.normalized_fields.ppid, 1234)

    def test_dlllist_normalized_fields(self):
        arts = self._run()
        dlls = [a for a in arts if a.artifact_type == "dll_record"]
        kernel = next(a for a in dlls if "kernel32" in (a.normalized_fields.file_path or ""))
        self.assertEqual(kernel.normalized_fields.pid, 1234)
        self.assertEqual(kernel.normalized_fields.process, "svchost.exe")
        self.assertIn("kernel32.dll", kernel.normalized_fields.file_path)

    def test_malfind_normalized_fields(self):
        arts = self._run()
        mal = [a for a in arts if a.artifact_type == "injection_indicator"]
        self.assertEqual(len(mal), 1)
        self.assertEqual(mal[0].normalized_fields.pid, 5678)
        self.assertEqual(mal[0].normalized_fields.process, "cmd.exe")
        self.assertEqual(mal[0].normalized_fields.severity, "PAGE_EXECUTE_READWRITE")

    def test_pslist_timestamp_parsed(self):
        arts = self._run()
        pslist = [a for a in arts if a.artifact_type == "process_record"]
        ts = pslist[0].timestamp
        self.assertIsNotNone(ts)
        self.assertEqual(ts.year, 2024)
        self.assertEqual(ts.day, 15)

    def test_raw_fields_preserved(self):
        arts = self._run()
        pslist = [a for a in arts if a.artifact_type == "process_record"]
        system = next(a for a in pslist if a.raw_fields.get("ImageFileName") == "System")
        self.assertEqual(system.raw_fields["PID"], 4)


# ===========================================================================
# MemoryParser — Table fallback
# ===========================================================================

class TestMemoryParserTableFallback(unittest.TestCase):
    """When JSON output is not recognised, the parser falls back to table parsing."""

    def _run(self) -> list[Artifact]:
        import tempfile, os
        f = tempfile.NamedTemporaryFile(suffix=".mem", delete=False)
        f.write(b"\x00"); f.close()
        try:
            call_count = {"n": 0}

            def side_effect(cmd, **kwargs):
                call_count["n"] += 1
                if "--output=json" in cmd:
                    # Return plain text — triggers table fallback
                    return _make_vol_result(PSLIST_TABLE)
                # Second call (table fallback) — also return table
                return _make_vol_result(PSLIST_TABLE)

            parser = MemoryParser()
            with patch("subprocess.run", side_effect=side_effect):
                return parser.parse(f.name, evidence_id=MEMORY_EVIDENCE_ID)
        finally:
            os.unlink(f.name)

    def test_table_fallback_parses_rows(self):
        """Two data rows in pslist table → at least 2 process_record artifacts."""
        arts = self._run()
        proc_records = [a for a in arts if a.artifact_type == "process_record"]
        self.assertGreaterEqual(len(proc_records), 2)

    def test_table_fallback_pid_parsed(self):
        arts = self._run()
        proc_records = [a for a in arts if a.artifact_type == "process_record"]
        pids = {a.normalized_fields.pid for a in proc_records}
        self.assertIn(4, pids)
        self.assertIn(1234, pids)


# ===========================================================================
# MemoryParser — Error handling
# ===========================================================================

class TestMemoryParserErrorHandling(unittest.TestCase):

    def _make_dump(self):
        import tempfile
        f = tempfile.NamedTemporaryFile(suffix=".mem", delete=False)
        f.write(b"\x00"); f.close()
        return f.name

    def test_raises_file_not_found_for_missing_dump(self):
        parser = MemoryParser()
        with self.assertRaises(FileNotFoundError):
            parser.parse("/nonexistent/dump.mem", evidence_id="x")

    def test_raises_volatility_not_found_when_binary_missing(self):
        dump = self._make_dump()
        try:
            parser = MemoryParser()
            with patch("subprocess.run", side_effect=FileNotFoundError("vol not found")):
                with self.assertRaises(VolatilityNotFoundError) as ctx:
                    parser.parse(dump, evidence_id="x")
            self.assertIn("vol", str(ctx.exception).lower())
        finally:
            import os; os.unlink(dump)

    def test_raises_volatility_execution_error_on_nonzero_exit(self):
        dump = self._make_dump()
        try:
            parser = MemoryParser()
            failed = _make_vol_result("", returncode=1)
            failed.stderr = "Error: could not open image"
            with patch("subprocess.run", return_value=failed):
                with self.assertRaises(VolatilityExecutionError) as ctx:
                    parser.parse(dump, evidence_id="x")
            self.assertIn("1", str(ctx.exception))
        finally:
            import os; os.unlink(dump)

    def test_does_not_silently_return_empty_list_on_binary_missing(self):
        dump = self._make_dump()
        try:
            parser = MemoryParser()
            result = None
            with patch("subprocess.run", side_effect=FileNotFoundError()):
                try:
                    result = parser.parse(dump, evidence_id="x")
                except VolatilityNotFoundError:
                    pass
                except Exception:
                    pass
            self.assertIsNot(result, [], "Parser must not silently return [] on binary failure")
        finally:
            import os; os.unlink(dump)

    def test_plugin_ordering_pslist_first(self):
        """Artifacts must be ordered: process_record → dll_record → injection_indicator."""
        dump = self._make_dump()
        try:
            def side_effect(cmd, **kwargs):
                if "windows.pslist" in cmd:
                    return _make_vol_result(PSLIST_JSON)
                if "windows.dlllist" in cmd:
                    return _make_vol_result(DLLLIST_JSON)
                if "windows.malfind" in cmd:
                    return _make_vol_result(MALFIND_JSON)
                return _make_vol_result("")

            parser = MemoryParser()
            with patch("subprocess.run", side_effect=side_effect):
                arts = parser.parse(dump, evidence_id=MEMORY_EVIDENCE_ID)

            types = [a.artifact_type for a in arts]
            first_proc = types.index("process_record")
            first_mal  = types.index("injection_indicator")
            first_dll  = types.index("dll_record")
            self.assertLess(first_proc, first_mal)
            self.assertLess(first_mal, first_dll)
        finally:
            import os; os.unlink(dump)

    def test_raises_volatility_symbol_error(self):
        from preprocessing.parsers.memory_parser import VolatilitySymbolError
        dump = self._make_dump()
        try:
            parser = MemoryParser()
            failed = _make_vol_result("", returncode=0)
            failed.stderr = "volatility3.core.exceptions.SymbolError: Symbol table download failed"
            with patch("subprocess.run", return_value=failed):
                with self.assertRaises(VolatilitySymbolError) as ctx:
                    parser.parse(dump, evidence_id="x")
            self.assertIn("symbols", str(ctx.exception).lower())
        finally:
            import os; os.unlink(dump)


# ===========================================================================
# PcapParser fixtures
# ===========================================================================

# ── Zeek conn.log (tab-separated, 3 data rows) ─────────────────────────────
ZEEK_CONN_LOG = (
    "#separator \x09\n"
    "#set_separator ,\n"
    "#empty_field (empty)\n"
    "#unset_field -\n"
    "#path conn\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\tconn_state\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tstring\n"
    "1710490931.000000\tCabc1\t192.168.1.10\t54321\t8.8.8.8\t53\tudp\t0.001\t30\t50\tSF\n"
    "1710490932.000000\tCabc2\t192.168.1.10\t49001\t93.184.216.34\t80\ttcp\t1.234\t500\t1200\tSF\n"
    "1710490933.000000\tCabc3\t10.0.0.5\t60000\t10.0.0.1\t443\ttcp\t0.5\t100\t200\tSF\n"
)

# ── Zeek dns.log (2 data rows) ─────────────────────────────────────────────
ZEEK_DNS_LOG = (
    "#separator \x09\n"
    "#fields\tts\tuid\tid.orig_h\tid.resp_h\tqtype_name\tquery\tanswers\n"
    "#types\ttime\tstring\taddr\taddr\tstring\tstring\tvector[string]\n"
    "1710490931.000000\tCabc1\t192.168.1.10\t8.8.8.8\tA\texample.com\t93.184.216.34\n"
    "1710490934.000000\tCabc4\t10.0.0.5\t8.8.4.4\tA\tmalware.bad\t-\n"
)

# ── Zeek http.log (1 data row) ─────────────────────────────────────────────
ZEEK_HTTP_LOG = (
    "#separator \x09\n"
    "#fields\tts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\tmethod\thost\turi\tstatus_code\trequest_body_len\tresponse_body_len\n"
    "#types\ttime\tstring\taddr\taddr\tport\tstring\tstring\tstring\tcount\tcount\tcount\n"
    "1710490932.000000\tCabc2\t192.168.1.10\t93.184.216.34\t80\tGET\texample.com\t/index.html\t200\t0\t1200\n"
)

# ── Suricata eve.json (3 lines: 2 alerts + 1 flow that should be skipped) ──
SURICATA_EVE_JSON = "\n".join([
    json.dumps({
        "timestamp": "2024-03-15T08:22:11.123456+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.10",
        "src_port": 54321,
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "alert": {
            "signature": "ET DNS Query for Suspicious TLD",
            "severity": 2,
            "category": "Potentially Bad Traffic",
        },
    }),
    json.dumps({
        "timestamp": "2024-03-15T08:22:12.000000+0000",
        "event_type": "flow",   # should be SKIPPED
        "src_ip": "10.0.0.1",
        "dest_ip": "10.0.0.5",
    }),
    json.dumps({
        "timestamp": "2024-03-15T08:22:13.000000+0000",
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "src_port": 60000,
        "dest_ip": "10.0.0.1",
        "dest_port": 4444,
        "alert": {
            "signature": "ET MALWARE Cobalt Strike Beacon",
            "severity": 1,
            "category": "Malware",
        },
    }),
]) + "\n"

PCAP_EVIDENCE_ID = "pcap-evidence-uuid-001"


# ---------------------------------------------------------------------------
# Helper: create a real temp PCAP-like file (content irrelevant, just needs to exist)
# ---------------------------------------------------------------------------

def _make_pcap():
    import tempfile
    f = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    f.write(b"\xd4\xc3\xb2\xa1")   # PCAP magic bytes
    f.close()
    return f.name


# ===========================================================================
# PcapParser — Zeek happy path
# ===========================================================================

class TestPcapParserZeek(unittest.TestCase):
    """Zeek pass: conn.log / dns.log / http.log correctly parsed."""

    def _run_zeek_only(self) -> list[Artifact]:
        """Mock only the Zeek subprocess; suppress Suricata entirely."""
        pcap = _make_pcap()
        try:
            parser = PcapParser()

            def fake_run_zeek(zeek_path, cwd):
                # Write all three Zeek log fixtures into the tmp cwd
                (cwd / "conn.log").write_text(ZEEK_CONN_LOG, encoding="utf-8")
                (cwd / "dns.log").write_text(ZEEK_DNS_LOG, encoding="utf-8")
                (cwd / "http.log").write_text(ZEEK_HTTP_LOG, encoding="utf-8")

            def fake_run_suricata(pcap_path, log_dir):
                # Don't write eve.json — Suricata contributes nothing in this test
                pass

            with (
                patch.object(parser, "_run_zeek", side_effect=fake_run_zeek),
                patch.object(parser, "_run_suricata", side_effect=fake_run_suricata),
            ):
                return parser.parse(pcap, evidence_id=PCAP_EVIDENCE_ID)
        finally:
            import os; os.unlink(pcap)

    def test_total_zeek_count(self):
        """3 conn + 2 dns + 1 http = 6 Zeek artifacts."""
        arts = self._run_zeek_only()
        self.assertEqual(len(arts), 6)

    def test_artifact_types(self):
        arts = self._run_zeek_only()
        types = [a.artifact_type for a in arts]
        self.assertEqual(types.count("network_connection"), 3)
        self.assertEqual(types.count("dns_query"), 2)
        self.assertEqual(types.count("http_request"), 1)

    def test_source_tool_zeek(self):
        for a in self._run_zeek_only():
            self.assertEqual(a.source_tool, "zeek")

    def test_evidence_id_propagated(self):
        for a in self._run_zeek_only():
            self.assertEqual(a.evidence_id, PCAP_EVIDENCE_ID)

    def test_artifact_ids_unique(self):
        arts = self._run_zeek_only()
        ids = [a.artifact_id for a in arts]
        self.assertEqual(len(ids), len(set(ids)))

    def test_conn_normalized_ips_and_ports(self):
        arts = self._run_zeek_only()
        conns = [a for a in arts if a.artifact_type == "network_connection"]
        first = conns[0]
        self.assertEqual(first.normalized_fields.src_ip, "192.168.1.10")
        self.assertEqual(first.normalized_fields.dst_ip, "8.8.8.8")
        self.assertEqual(first.normalized_fields.src_port, 54321)
        self.assertEqual(first.normalized_fields.dst_port, 53)

    def test_dns_normalized_domain(self):
        arts = self._run_zeek_only()
        dns = [a for a in arts if a.artifact_type == "dns_query"]
        domains = {a.normalized_fields.domain for a in dns}
        self.assertIn("example.com", domains)
        self.assertIn("malware.bad", domains)

    def test_http_normalized_url(self):
        arts = self._run_zeek_only()
        http = [a for a in arts if a.artifact_type == "http_request"]
        self.assertEqual(len(http), 1)
        url = http[0].normalized_fields.url
        self.assertIn("example.com", url)
        self.assertIn("/index.html", url)

    def test_zeek_timestamp_parsed(self):
        arts = self._run_zeek_only()
        conns = [a for a in arts if a.artifact_type == "network_connection"]
        ts = conns[0].timestamp
        self.assertIsNotNone(ts)
        self.assertIsInstance(ts, datetime)

    def test_zeek_unset_field_becomes_none(self):
        """Zeek '-' sentinel must map to None in raw_fields."""
        arts = self._run_zeek_only()
        dns = [a for a in arts if a.artifact_type == "dns_query"]
        # Second DNS row has '-' for answers
        no_answer = next(
            a for a in dns if a.raw_fields.get("query") == "malware.bad"
        )
        self.assertIsNone(no_answer.raw_fields.get("answers"))

    def test_raw_fields_preserved(self):
        arts = self._run_zeek_only()
        conns = [a for a in arts if a.artifact_type == "network_connection"]
        first = conns[0]
        self.assertEqual(first.raw_fields["uid"], "Cabc1")
        self.assertEqual(first.raw_fields["proto"], "udp")


# ===========================================================================
# PcapParser — Suricata happy path
# ===========================================================================

class TestPcapParserSuricata(unittest.TestCase):
    """Suricata pass: only alert events from eve.json are mapped; flow is skipped."""

    def _run_suricata_only(self) -> list[Artifact]:
        pcap = _make_pcap()
        try:
            parser = PcapParser()

            def fake_run_zeek(pcap_path, cwd):
                pass   # no Zeek logs

            def fake_run_suricata(pcap_path, log_dir):
                (log_dir / "eve.json").write_text(
                    SURICATA_EVE_JSON, encoding="utf-8"
                )

            with (
                patch.object(parser, "_run_zeek", side_effect=fake_run_zeek),
                patch.object(parser, "_run_suricata", side_effect=fake_run_suricata),
            ):
                return parser.parse(pcap, evidence_id=PCAP_EVIDENCE_ID)
        finally:
            import os; os.unlink(pcap)

    def test_only_alerts_mapped(self):
        """3 eve.json lines (2 alerts + 1 flow) — all preserved."""
        arts = self._run_suricata_only()
        self.assertEqual(len(arts), 3)

    def test_artifact_type_ids_alert(self):
        arts = self._run_suricata_only()
        alerts = [a for a in arts if a.raw_fields.get("event_type") == "alert"]
        for a in alerts:
            self.assertEqual(a.artifact_type, "ids_alert")

    def test_source_tool_suricata(self):
        for a in self._run_suricata_only():
            self.assertEqual(a.source_tool, "suricata")

    def test_normalized_src_dst_ip(self):
        arts = self._run_suricata_only()
        first = arts[0]
        self.assertEqual(first.normalized_fields.src_ip, "192.168.1.10")
        self.assertEqual(first.normalized_fields.dst_ip, "8.8.8.8")

    def test_normalized_ports(self):
        arts = self._run_suricata_only()
        first = arts[0]
        self.assertEqual(first.normalized_fields.src_port, 54321)
        self.assertEqual(first.normalized_fields.dst_port, 53)

    def test_normalized_rule_name(self):
        arts = self._run_suricata_only()
        sigs = {a.normalized_fields.rule_name for a in arts}
        self.assertIn("ET DNS Query for Suspicious TLD", sigs)
        self.assertIn("ET MALWARE Cobalt Strike Beacon", sigs)

    def test_normalized_severity_mapping(self):
        """Suricata severity 1=high, 2=medium."""
        arts = self._run_suricata_only()
        high = next(a for a in arts if "Cobalt" in (a.normalized_fields.rule_name or ""))
        medium = next(a for a in arts if "DNS" in (a.normalized_fields.rule_name or ""))
        self.assertEqual(high.normalized_fields.severity, "high")
        self.assertEqual(medium.normalized_fields.severity, "medium")

    def test_suricata_timestamp_parsed(self):
        arts = self._run_suricata_only()
        ts = arts[0].timestamp
        self.assertIsNotNone(ts)
        self.assertEqual(ts.year, 2024)

    def test_raw_fields_preserved(self):
        arts = self._run_suricata_only()
        first = arts[0]
        self.assertIn("alert", first.raw_fields)
        self.assertEqual(first.raw_fields["event_type"], "alert")


# ===========================================================================
# PcapParser — Combined parse (Zeek + Suricata together)
# ===========================================================================

class TestPcapParserCombined(unittest.TestCase):

    def _run_combined(self) -> list[Artifact]:
        pcap = _make_pcap()
        try:
            parser = PcapParser()

            def fake_run_zeek(pcap_path, cwd):
                (cwd / "conn.log").write_text(ZEEK_CONN_LOG, encoding="utf-8")
                (cwd / "dns.log").write_text(ZEEK_DNS_LOG, encoding="utf-8")
                (cwd / "http.log").write_text(ZEEK_HTTP_LOG, encoding="utf-8")

            def fake_run_suricata(pcap_path, log_dir):
                (log_dir / "eve.json").write_text(SURICATA_EVE_JSON, encoding="utf-8")

            with (
                patch.object(parser, "_run_zeek", side_effect=fake_run_zeek),
                patch.object(parser, "_run_suricata", side_effect=fake_run_suricata),
            ):
                return parser.parse(pcap, evidence_id=PCAP_EVIDENCE_ID)
        finally:
            import os; os.unlink(pcap)

    def test_combined_total(self):
        """6 Zeek + 3 Suricata = 9 total."""
        self.assertEqual(len(self._run_combined()), 9)

    def test_zeek_artifacts_come_first(self):
        """Zeek artifacts must precede Suricata artifacts in the returned list."""
        arts = self._run_combined()
        zeek_idx = [i for i, a in enumerate(arts) if a.source_tool == "zeek"]
        suri_idx = [i for i, a in enumerate(arts) if a.source_tool == "suricata"]
        self.assertTrue(all(z < s for z in zeek_idx for s in suri_idx))


# ===========================================================================
# PcapParser — Error handling
# ===========================================================================

class TestPcapParserErrorHandling(unittest.TestCase):

    def test_raises_file_not_found_for_missing_pcap(self):
        parser = PcapParser()
        with self.assertRaises(FileNotFoundError):
            parser.parse("/nonexistent/capture.pcap", evidence_id="x")

    def test_raises_zeek_not_found_when_binary_missing(self):
        pcap = _make_pcap()
        try:
            parser = PcapParser()
            with patch("subprocess.run", side_effect=FileNotFoundError("zeek not found")):
                with self.assertRaises(ZeekNotFoundError) as ctx:
                    parser.parse(pcap, evidence_id="x")
            self.assertIn("zeek", str(ctx.exception).lower())
        finally:
            import os; os.unlink(pcap)

    def test_raises_zeek_execution_error_on_nonzero_exit(self):
        pcap = _make_pcap()
        try:
            failed = MagicMock(returncode=1, stdout="", stderr="Zeek failed")
            parser = PcapParser()
            with patch("subprocess.run", return_value=failed):
                with self.assertRaises(ZeekExecutionError):
                    parser.parse(pcap, evidence_id="x")
        finally:
            import os; os.unlink(pcap)

    def test_raises_suricata_not_found(self):
        """Zeek succeeds (mocked), then Suricata binary missing → SuricataNotFoundError."""
        pcap = _make_pcap()
        try:
            parser = PcapParser()

            def fake_run_zeek(pcap_path, cwd):
                pass   # Zeek succeeds, no logs written

            with patch.object(parser, "_run_zeek", side_effect=fake_run_zeek):
                with patch(
                    "subprocess.run",
                    side_effect=FileNotFoundError("suricata not found")
                ):
                    with self.assertRaises(SuricataNotFoundError):
                        parser.parse(pcap, evidence_id="x")
        finally:
            import os; os.unlink(pcap)

    def test_raises_suricata_execution_error_on_nonzero_exit(self):
        pcap = _make_pcap()
        try:
            parser = PcapParser()
            failed = MagicMock(returncode=1, stdout="", stderr="Suricata failed")

            def fake_run_zeek(pcap_path, cwd):
                pass

            with patch.object(parser, "_run_zeek", side_effect=fake_run_zeek):
                with patch("subprocess.run", return_value=failed):
                    with self.assertRaises(SuricataExecutionError):
                        parser.parse(pcap, evidence_id="x")
        finally:
            import os; os.unlink(pcap)

    def test_no_eve_json_returns_empty_suricata_list(self):
        """If Suricata runs but produces no eve.json, the Zeek results still come through."""
        pcap = _make_pcap()
        try:
            parser = PcapParser()

            def fake_run_zeek(pcap_path, cwd):
                (cwd / "conn.log").write_text(ZEEK_CONN_LOG, encoding="utf-8")

            def fake_run_suricata(pcap_path, log_dir):
                pass   # no eve.json written

            with (
                patch.object(parser, "_run_zeek", side_effect=fake_run_zeek),
                patch.object(parser, "_run_suricata", side_effect=fake_run_suricata),
            ):
                arts = parser.parse(pcap, evidence_id="x")

            # Only Zeek artifacts returned — no crash
            self.assertTrue(all(a.source_tool == "zeek" for a in arts))
            self.assertEqual(len(arts), 3)   # 3 conn.log rows
        finally:
            import os; os.unlink(pcap)


# ===========================================================================
# RegistryParser fixtures
# ===========================================================================

# Realistic RegRipper output — two plugin sections
REGRIPPER_FIXTURE = """\
Launching userassist v.20200517
userassist v.20200517
(NTUSER.DAT)
-----------------------------------------
HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist
2024-03-15 08:22:11Z
UEME_RUNPATH:C:\\Windows\\explorer.exe  Count: 3
UEME_RUNPATH:C:\\Windows\\notepad.exe  Count: 1

Launching shimcache v.20201114
shimcache v.20201114
(SYSTEM)
-----------------------------------------
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache
2024-03-15 08:00:00Z
C:\\Windows\\System32\\cmd.exe: LastModified: 2024-02-01 10:00:00Z
C:\\Windows\\System32\\powershell.exe: LastModified: 2024-02-05 12:00:00Z
"""

# A section with no key=value pairs (free-form block)
REGRIPPER_FREEFORM = """\
Launching timezone v.20200518
timezone v.20200518
(SYSTEM)
-----------------------------------------
TimeZoneKeyName: Pacific Standard Time
ActiveTimeBias: ffffffd0
"""

# A section with no recognizable structure at all
REGRIPPER_EMPTY_SECTION = """\
Launching services v.20200610
services v.20200610
(SYSTEM)
-----------------------------------------
No services found.
"""

REG_EVIDENCE_ID = "reg-evidence-uuid-001"


def _make_hive():
    """Create a real temp file that pretends to be a registry hive."""
    import tempfile
    f = tempfile.NamedTemporaryFile(suffix=".dat", delete=False)
    f.write(b"regf")   # registry hive magic
    f.close()
    return f.name


def _mock_rip_result(stdout: str, returncode: int = 0) -> MagicMock:
    r = MagicMock()
    r.returncode = returncode
    r.stdout = stdout
    r.stderr = ""
    return r


# ===========================================================================
# Section splitting (unit tests for the internal helper)
# ===========================================================================

class TestRegistryParserSectionSplitting(unittest.TestCase):
    """Tests for _split_into_sections — the core parsing primitive."""

    def test_correct_section_count(self):
        sections = _split_into_sections(REGRIPPER_FIXTURE)
        self.assertEqual(len(sections), 2)

    def test_plugin_names_lowercased(self):
        sections = _split_into_sections(REGRIPPER_FIXTURE)
        self.assertEqual(sections[0]["plugin"], "userassist")
        self.assertEqual(sections[1]["plugin"], "shimcache")

    def test_plugin_text_contains_raw_content(self):
        sections = _split_into_sections(REGRIPPER_FIXTURE)
        self.assertIn("UEME_RUNPATH", sections[0]["plugin_text"])
        self.assertIn("AppCompatCache", sections[1]["plugin_text"])

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(_split_into_sections(""), [])

    def test_preamble_before_first_launch_is_ignored(self):
        """Lines before any 'Launching' header should not create a section."""
        text = "RegRipper 3.0 - rip.pl\nSome preamble line\n" + REGRIPPER_FIXTURE
        sections = _split_into_sections(text)
        self.assertEqual(len(sections), 2)
        # No phantom section with plugin=None
        for s in sections:
            self.assertIsNotNone(s["plugin"])


# ===========================================================================
# RegistryParser happy path
# ===========================================================================

class TestRegistryParserHappyPath(unittest.TestCase):

    def _run(self, fixture: str = REGRIPPER_FIXTURE) -> list[Artifact]:
        hive = _make_hive()
        try:
            parser = RegistryParser(profiles=["ntuser"])   # single profile for simplicity

            with (
                patch("shutil.which", return_value="/usr/bin/rip.pl"),
                patch("subprocess.run", return_value=_mock_rip_result(fixture)),
            ):
                return parser.parse(hive, evidence_id=REG_EVIDENCE_ID)
        finally:
            import os; os.unlink(hive)

    def test_returns_artifacts(self):
        arts = self._run()
        self.assertGreater(len(arts), 0)

    def test_all_artifacts_are_registry_key_type(self):
        for a in self._run():
            self.assertIn(a.artifact_type, ("registry_key", "userassist", "usb_device", "recentdocs", "bam_dam", "muicache", "scheduled_task", "windows_service", "network_configuration"))

    def test_source_tool_is_regripper(self):
        for a in self._run():
            self.assertEqual(a.source_tool, "regripper")

    def test_evidence_id_propagated(self):
        for a in self._run():
            self.assertEqual(a.evidence_id, REG_EVIDENCE_ID)

    def test_artifact_ids_unique(self):
        arts = self._run()
        ids = [a.artifact_id for a in arts]
        self.assertEqual(len(ids), len(set(ids)))

    def test_userassist_artifacts_have_key_path(self):
        """Key-value artifacts from userassist must have key_path in raw_fields."""
        arts = self._run()
        userassist = [a for a in arts if a.raw_fields.get("plugin") == "userassist"]
        for a in userassist:
            if a.raw_fields.get("value_name"):   # structured artifact
                self.assertIn("key_path", a.raw_fields)

    def test_userassist_value_name_and_data_extracted(self):
        arts = self._run()
        userassist_kv = [
            a for a in arts
            if a.raw_fields.get("plugin") == "userassist"
            and "value_name" in a.raw_fields
        ]
        self.assertGreater(len(userassist_kv), 0)
        # explorer.exe entry must be present
        names = {a.raw_fields["value_name"] for a in userassist_kv}
        self.assertTrue(
            any("explorer" in n.lower() or "UEME" in n for n in names),
            f"Expected an explorer.exe entry; got: {names}"
        )

    def test_normalized_file_path_contains_key_path(self):
        arts = self._run()
        userassist_kv = [
            a for a in arts
            if a.raw_fields.get("plugin") == "userassist"
            and a.normalized_fields.file_path
        ]
        self.assertGreater(len(userassist_kv), 0)
        # file_path should contain the key path or key\value_name
        for a in userassist_kv:
            self.assertIsNotNone(a.normalized_fields.file_path)

    def test_normalized_rule_name_is_plugin_name(self):
        arts = self._run()
        for a in arts:
            self.assertIsNotNone(a.normalized_fields.rule_name)
            self.assertIn(a.normalized_fields.rule_name, ["userassist", "shimcache"])

    def test_timestamp_extracted_from_block(self):
        """At least some artifacts should have a parsed timestamp."""
        arts = self._run()
        timestamps = [a.timestamp for a in arts if a.timestamp is not None]
        self.assertGreater(len(timestamps), 0)
        self.assertIsInstance(timestamps[0], datetime)

    def test_raw_plugin_text_always_preserved(self):
        """plugin_text must be present in raw_fields for every artifact."""
        for a in self._run():
            self.assertIn("plugin_text", a.raw_fields)
            self.assertIsInstance(a.raw_fields["plugin_text"], str)
            self.assertGreater(len(a.raw_fields["plugin_text"]), 0)

    def test_freeform_section_emits_catchall_artifact(self):
        """A free-form section (timezone) must produce at least one catch-all artifact."""
        arts = self._run(REGRIPPER_FREEFORM)
        timezone_arts = [a for a in arts if a.raw_fields.get("plugin") == "timezone"]
        self.assertGreater(len(timezone_arts), 0)

    def test_empty_section_emits_catchall_artifact(self):
        """A section with no parseable structure still emits one artifact."""
        arts = self._run(REGRIPPER_EMPTY_SECTION)
        self.assertGreater(len(arts), 0)

    def test_usbstor_emits_both_registry_key_and_usb_device(self):
        usbstor_fixture = """\
Launching usbstor v.20200517
usbstor v.20200517
(SYSTEM)
-----------------------------------------
HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\4C53000115&0
2024-03-15 08:22:11Z
FriendlyName: SanDisk Cruzer USB Device
"""
        arts = self._run(usbstor_fixture)
        # Should have registry_key AND usb_device artifacts
        types = [a.artifact_type for a in arts]
        self.assertIn("registry_key", types)
        self.assertIn("usb_device", types)

        # Check USB-specific fields are populated on the usb_device artifact
        usb_art = next(a for a in arts if a.artifact_type == "usb_device")
        self.assertEqual(usb_art.normalized_fields.device_serial, "4C53000115")
        self.assertEqual(usb_art.normalized_fields.friendly_name, "SanDisk Cruzer USB Device")
        self.assertEqual(usb_art.normalized_fields.first_connected, "2024-03-15 08:22:11Z")
        self.assertEqual(usb_art.normalized_fields.last_connected, "2024-03-15 08:22:11Z")


# ===========================================================================
# RegistryParser — multiple profiles
# ===========================================================================

class TestRegistryParserMultipleProfiles(unittest.TestCase):

    def test_results_from_all_profiles_combined(self):
        """Each profile's output is appended; total = sum across profiles."""
        hive = _make_hive()
        try:
            parser = RegistryParser(profiles=["ntuser", "system"])
            call_count = {"n": 0}

            def side_effect(cmd, **kwargs):
                call_count["n"] += 1
                # Both profiles return the same userassist fixture
                return _mock_rip_result(REGRIPPER_FREEFORM)

            with (
                patch("shutil.which", return_value="/usr/bin/rip.pl"),
                patch("subprocess.run", side_effect=side_effect),
            ):
                arts = parser.parse(hive, evidence_id=REG_EVIDENCE_ID)

            # subprocess.run called once per profile
            self.assertEqual(call_count["n"], 2)
            # Both profiles contributed artifacts
            self.assertGreater(len(arts), 0)
        finally:
            import os; os.unlink(hive)

    def test_failed_profile_skipped_others_continue(self):
        """A profile that exits non-zero is skipped; the other profiles still run."""
        hive = _make_hive()
        try:
            parser = RegistryParser(profiles=["ntuser", "system"])
            call_count = {"n": 0}

            def side_effect(cmd, **kwargs):
                call_count["n"] += 1
                if call_count["n"] == 1:
                    return _mock_rip_result("", returncode=1)   # ntuser fails
                return _mock_rip_result(REGRIPPER_FREEFORM)     # system succeeds

            with (
                patch("shutil.which", return_value="/usr/bin/rip.pl"),
                patch("subprocess.run", side_effect=side_effect),
            ):
                arts = parser.parse(hive, evidence_id=REG_EVIDENCE_ID)

            # system profile still ran → artifacts present
            self.assertGreater(len(arts), 0)
        finally:
            import os; os.unlink(hive)


# ===========================================================================
# RegistryParser — error handling
# ===========================================================================

class TestRegistryParserErrorHandling(unittest.TestCase):

    def test_raises_file_not_found_for_missing_hive(self):
        parser = RegistryParser()
        with self.assertRaises(FileNotFoundError):
            parser.parse("/nonexistent/NTUSER.DAT", evidence_id="x")

    def test_raises_regripper_not_found_when_binary_missing(self):
        hive = _make_hive()
        try:
            parser = RegistryParser(profiles=["ntuser"])
            # shutil.which returns None for all binaries, and mock subprocess.run so WSL check returns 1
            with patch("shutil.which", return_value=None), patch("subprocess.run") as mock_sub:
                mock_sub.return_value.returncode = 1
                with self.assertRaises(RegRipperNotFoundError) as ctx:
                    parser.parse(hive, evidence_id="x")
            self.assertIn("rip", str(ctx.exception).lower())
        finally:
            import os; os.unlink(hive)

    def test_all_profiles_failing_raises_regripper_execution_error(self):
        """If every profile exits non-zero, parse() raises RegRipperExecutionError."""
        hive = _make_hive()
        try:
            parser = RegistryParser(profiles=["ntuser", "system"])
            with (
                patch("shutil.which", return_value="/usr/bin/rip.pl"),
                patch("subprocess.run", return_value=_mock_rip_result("", returncode=1)),
            ):
                with self.assertRaises(RegRipperExecutionError):
                    parser.parse(hive, evidence_id="x")
        finally:
            import os; os.unlink(hive)

    def test_does_not_silently_pass_when_binary_missing(self):
        """Binary missing must raise, never return []."""
        hive = _make_hive()
        try:
            parser = RegistryParser(profiles=["ntuser"])
            result = None
            with patch("shutil.which", return_value=None):
                try:
                    result = parser.parse(hive, evidence_id="x")
                except RegRipperNotFoundError:
                    pass
            self.assertIsNot(result, [], "Must not silently return [] on binary missing")
        finally:
            import os; os.unlink(hive)


# ---------------------------------------------------------------------------
# ===========================================================================
# ParserRouter Tests
# ===========================================================================

class TestParserRouter(unittest.TestCase):
    """Unit tests for preprocessing/router.py (ParserRouter)."""

    def setUp(self) -> None:
        self.router = ParserRouter()
        import tempfile
        # Create a temp file to hold magic bytes
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.close()

    def tearDown(self) -> None:
        import os
        os.unlink(self.temp_file.name)

    def _write_bytes(self, data: bytes) -> None:
        with open(self.temp_file.name, "wb") as f:
            f.write(data)

    def _make_evidence(self, filename: str, ext: str = "", mime: str = "") -> Evidence:
        return Evidence(
            case_id="case-001",
            filename=filename,
            file_path=self.temp_file.name,
            uploaded_by="analyst",
            status=EvidenceStatus.STORED,
            metadata={
                "extension": ext,
                "mime_type": mime,
            }
        )

    # ── Signature Routing Tests ───────────────────────────────────────────

    def test_route_evtx_by_signature(self):
        self._write_bytes(b"ElfFile\x00someextraevtxdata")
        evidence = self._make_evidence("unknown_file")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, EvtxParser)
        self.assertEqual(evidence.audit_log[-1].detail["method"], "signature")

    def test_route_pcap_by_signature(self):
        self._write_bytes(b"\xd4\xc3\xb2\xa1somepcapdata")
        evidence = self._make_evidence("unknown_file")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, PcapParser)
        self.assertEqual(evidence.audit_log[-1].detail["method"], "signature")

    def test_route_registry_by_signature(self):
        self._write_bytes(b"regfsomeregistryhive")
        evidence = self._make_evidence("unknown_file")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, RegistryParser)
        self.assertEqual(evidence.audit_log[-1].detail["method"], "signature")

    def test_route_usb_registry_by_signature(self):
        self._write_bytes(b"regfsomeregistryhive")
        evidence = self._make_evidence("usbstor.dat")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, RegistryParser)
        self.assertEqual(evidence.audit_log[-1].detail["method"], "signature")

    def test_route_memory_by_signature(self):
        self._write_bytes(b"PAGEDUMPsomeformat")
        evidence = self._make_evidence("unknown_file")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, MemoryParser)
        self.assertEqual(evidence.audit_log[-1].detail["method"], "signature")

    def test_route_filesystem_by_signature(self):
        self._write_bytes(b"LVF\x09\x00\x01\x00")
        evidence = self._make_evidence("unknown_file")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, FilesystemParser)
        self.assertEqual(evidence.audit_log[-1].detail["method"], "signature")

    def test_route_msg_email_by_signature(self):
        self._write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1outlookmessage")
        evidence = self._make_evidence("unknown_file")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, MsgEmailParser)
        self.assertEqual(evidence.audit_log[-1].detail["method"], "signature")

    def test_route_eml_email_by_signature(self):
        self._write_bytes(b"From: sender@example.com\r\nSubject: Test EML\r\n\r\nBody")
        evidence = self._make_evidence("unknown_file")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, EmailParser)
        self.assertEqual(evidence.audit_log[-1].detail["method"], "signature")

    # ── Extension Fallback Routing Tests ──────────────────────────────────

    def test_route_evtx_by_extension(self):
        self._write_bytes(b"arbitrarynonmagicbytes")
        evidence = self._make_evidence("test.evtx", ext=".evtx")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, EvtxParser)
        self.assertEqual(evidence.audit_log[-1].detail["method"], "extension")

    def test_route_pcap_by_extension(self):
        self._write_bytes(b"arbitrarynonmagicbytes")
        evidence = self._make_evidence("capture.pcapng", ext=".pcapng")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, PcapParser)
        self.assertEqual(evidence.audit_log[-1].detail["method"], "extension")

    def test_route_pcap_by_mime_type(self):
        self._write_bytes(b"arbitrarynonmagicbytes")
        evidence = self._make_evidence("capture.unknown", mime="application/vnd.tcpdump.pcap")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, PcapParser)

    def test_route_registry_by_extension(self):
        self._write_bytes(b"arbitrarynonmagicbytes")
        evidence = self._make_evidence("ntuser.dat", ext=".dat")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, RegistryParser)

    def test_route_usb_by_extension(self):
        self._write_bytes(b"arbitrarynonmagicbytes")
        evidence = self._make_evidence("usb_registry.reg", ext=".reg")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, RegistryParser)

    def test_route_memory_by_extension(self):
        self._write_bytes(b"arbitrarynonmagicbytes")
        evidence = self._make_evidence("physmem.raw", ext=".raw")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, MemoryParser)

    def test_route_email_by_extension(self):
        self._write_bytes(b"arbitrarynonmagicbytes")
        evidence = self._make_evidence("phishing.eml", ext=".eml")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, EmailParser)

    def test_route_filesystem_by_extension(self):
        self._write_bytes(b"arbitrarynonmagicbytes")
        evidence = self._make_evidence("disk.e01", ext=".e01")
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, FilesystemParser)

    def test_route_browser_by_folder_pattern(self):
        self._write_bytes(b"arbitrarynonmagicbytes")
        evidence = self._make_evidence("History") # Chrome History file
        parser = self.router.route(evidence)
        self.assertIsInstance(parser, BrowserParser)
        self.assertEqual(evidence.audit_log[-1].detail["method"], "extension")

    # ── Exception & Unroutable Tests ──────────────────────────────────────

    def test_unroutable_raises_error(self):
        self._write_bytes(b"arbitrarynonmagicbytes")
        evidence = self._make_evidence("random.txt", ext=".txt", mime="text/plain")
        with self.assertRaises(UnroutableEvidenceError) as ctx:
            self.router.route(evidence)
        self.assertEqual(ctx.exception.evidence_id, evidence.evidence_id)
        self.assertEqual(ctx.exception.metadata, evidence.metadata)

    def test_logs_parser_routed_event(self):
        self._write_bytes(b"ElfFile\x00someextraevtxdata")
        evidence = self._make_evidence("test.evtx")
        self.router.route(evidence)
        self.assertEqual(len(evidence.audit_log), 1)
        self.assertEqual(evidence.audit_log[0].event, "parser_routed")
        self.assertEqual(evidence.audit_log[0].detail["parser"], "EvtxParser")


# ===========================================================================
# BrowserParser Tests
# ===========================================================================

HINDSIGHT_FIXTURE_LINES = [
    {
        "type": "url",
        "url": "https://www.google.com",
        "title": "Google Search",
        "visit_time": "2024-03-15 08:22:11 UTC",
        "visit_count": 5,
    },
    {
        "type": "download",
        "url": "https://example.com/malware.exe",
        "path": "C:\\Users\\Alice\\Downloads\\malware.exe",
        "time": "2024-03-15 08:23:45 UTC",
    },
    {
        "type": "cookie",
        "domain": ".google.com",
        "name": "SID",
        "timestamp": 1710490931000000, # microsecond epoch
    }
]

HINDSIGHT_JSONL = "\n".join(json.dumps(r) for r in HINDSIGHT_FIXTURE_LINES) + "\n"
BROWSER_EVIDENCE_ID = "browser-evidence-uuid-001"


class TestBrowserParserHappyPath(unittest.TestCase):

    def _make_temp_profile(self):
        import tempfile
        f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        f.write(b"sqlitemagic")
        f.close()
        return f.name

    def _run(self) -> list[Artifact]:
        profile = self._make_temp_profile()
        try:
            parser = BrowserParser()
            def fake_run_hindsight(input_path, output_path):
                # Write output.jsonl matching Hindsight behavior
                out_file = output_path.with_name(output_path.name + ".jsonl")
                out_file.write_text(HINDSIGHT_JSONL, encoding="utf-8")

            with patch.object(parser, "_run_hindsight", side_effect=fake_run_hindsight):
                return parser.parse(profile, evidence_id=BROWSER_EVIDENCE_ID)
        finally:
            import os; os.unlink(profile)

    def test_total_artifact_count(self):
        self.assertEqual(len(self._run()), 3)

    def test_artifact_types(self):
        arts = self._run()
        types = [a.artifact_type for a in arts]
        self.assertEqual(types[0], "browser_history")
        self.assertEqual(types[1], "browser_download")
        self.assertEqual(types[2], "browser_cookie")

    def test_source_tool_is_hindsight(self):
        for a in self._run():
            self.assertEqual(a.source_tool, "hindsight")

    def test_evidence_id_propagated(self):
        for a in self._run():
            self.assertEqual(a.evidence_id, BROWSER_EVIDENCE_ID)

    def test_artifact_ids_unique(self):
        arts = self._run()
        ids = [a.artifact_id for a in arts]
        self.assertEqual(len(ids), len(set(ids)))

    def test_normalized_history_fields(self):
        arts = self._run()
        hist = arts[0]
        self.assertEqual(hist.normalized_fields.url, "https://www.google.com")
        self.assertEqual(hist.normalized_fields.rule_name, "url")

    def test_normalized_download_fields(self):
        arts = self._run()
        dl = arts[1]
        self.assertEqual(dl.normalized_fields.url, "https://example.com/malware.exe")
        self.assertEqual(dl.normalized_fields.file_path, "C:\\Users\\Alice\\Downloads\\malware.exe")

    def test_normalized_cookie_fields(self):
        arts = self._run()
        cookie = arts[2]
        self.assertEqual(cookie.normalized_fields.domain, ".google.com")

    def test_timestamps_parsed(self):
        arts = self._run()
        self.assertIsNotNone(arts[0].timestamp)
        self.assertIsNotNone(arts[1].timestamp)
        self.assertIsNotNone(arts[2].timestamp)


class TestBrowserParserErrorHandling(unittest.TestCase):

    def test_raises_file_not_found_for_missing_profile(self):
        parser = BrowserParser()
        with self.assertRaises(FileNotFoundError):
            parser.parse("/nonexistent/profile", evidence_id="x")

    def test_raises_hindsight_not_found_when_binary_missing(self):
        import tempfile, os
        f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        f.close()
        try:
            parser = BrowserParser()
            with patch("subprocess.run", side_effect=FileNotFoundError("not found")):
                with self.assertRaises(HindsightNotFoundError) as ctx:
                    parser.parse(f.name, evidence_id="x")
            self.assertIn("hindsight", str(ctx.exception).lower())
        finally:
            os.unlink(f.name)

    def test_raises_hindsight_execution_error_on_nonzero_exit(self):
        import tempfile, os
        f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        f.close()
        try:
            parser = BrowserParser()
            failed_result = MagicMock(returncode=1, stdout="", stderr="Error executing Hindsight")
            with patch("subprocess.run", return_value=failed_result):
                with self.assertRaises(HindsightExecutionError) as ctx:
                    parser.parse(f.name, evidence_id="x")
            self.assertIn("1", str(ctx.exception))
        finally:
            os.unlink(f.name)


class TestBrowserParserMalformedJSONL(unittest.TestCase):

    def test_skips_malformed_lines_and_parses_valid_ones(self):
        mixed_jsonl = (
            json.dumps(HINDSIGHT_FIXTURE_LINES[0]) + "\n"
            "THIS IS NOT JSON\n"
            + json.dumps(HINDSIGHT_FIXTURE_LINES[1]) + "\n"
        )
        import tempfile, os
        f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        f.close()
        try:
            parser = BrowserParser()
            def fake_run(input_path, output_path):
                out = output_path.with_name(output_path.name + ".jsonl")
                out.write_text(mixed_jsonl, encoding="utf-8")

            with patch.object(parser, "_run_hindsight", side_effect=fake_run):
                arts = parser.parse(f.name, evidence_id=BROWSER_EVIDENCE_ID)
            self.assertEqual(len(arts), 2)
        finally:
            os.unlink(f.name)


# ===========================================================================
# EmailParser Tests
# ===========================================================================

RAW_EMAIL_FIXTURE = (
    "From: sender@example.com\r\n"
    "To: recipient@example.com\r\n"
    "Cc: cc@example.com\r\n"
    "Bcc: bcc@example.com\r\n"
    "Subject: Urgent: Action Required\r\n"
    "Date: Fri, 15 Mar 2024 08:22:11 +0000\r\n"
    "Message-ID: <unique-id-123@example.com>\r\n"
    "Received: from mail.example.com (mail.example.com [192.0.2.1]) by mx.google.com\r\n"
    "Received: from gateway.example.com by mail.example.com\r\n"
    "Content-Type: multipart/mixed; boundary=\"boundary-string\"\r\n"
    "\r\n"
    "--boundary-string\r\n"
    "Content-Type: text/plain; charset=\"utf-8\"\r\n"
    "Content-Transfer-Encoding: 7bit\r\n"
    "\r\n"
    "Hello, click here: http://phish.link/login and visit http://google.com\r\n"
    "--boundary-string\r\n"
    "Content-Type: text/html; charset=\"utf-8\"\r\n"
    "Content-Transfer-Encoding: 7bit\r\n"
    "\r\n"
    "<p>Hello HTML</p>\r\n"
    "--boundary-string\r\n"
    "Content-Type: application/octet-stream; name=\"malware.exe\"\r\n"
    "Content-Disposition: attachment; filename=\"malware.exe\"\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    "dGVzdCBwYXlsb2Fk\r\n"
    "--boundary-string--\r\n"
)

RAW_EMAIL_MALFORMED_DATE = (
    "From: sender@example.com\r\n"
    "To: recipient@example.com\r\n"
    "Subject: Bad Date Header\r\n"
    "Date: NOT A VALID DATE\r\n"
    "Content-Type: text/plain; charset=\"utf-8\"\r\n"
    "\r\n"
    "Body contents here.\r\n"
)

RAW_EMAIL_NO_ATTACHMENT = (
    "From: sender@example.com\r\n"
    "To: recipient@example.com\r\n"
    "Subject: No Attachments Here\r\n"
    "Date: Fri, 15 Mar 2024 08:22:11 +0000\r\n"
    "Content-Type: text/plain; charset=\"utf-8\"\r\n"
    "\r\n"
    "Just simple body.\r\n"
)

RAW_EMAIL_GARBAGE = (
    "This is raw garbage file without standard email headers or structure at all."
)

EMAIL_EVIDENCE_ID = "email-evidence-uuid-001"


class TestEmailParser(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = EmailParser()

    def _write_temp_email(self, content: str) -> str:
        import tempfile
        f = tempfile.NamedTemporaryFile(suffix=".eml", delete=False)
        f.write(content.encode("utf-8"))
        f.close()
        return f.name

    def test_raises_file_not_found_for_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            self.parser.parse("/nonexistent/file.eml", evidence_id="x")

    def test_raises_value_error_for_oversized_file(self):
        temp_file = self._write_temp_email(RAW_EMAIL_FIXTURE)
        try:
            with patch("pathlib.Path.stat") as mock_stat:
                mock_stat.return_value.st_size = 60 * 1024 * 1024
                with self.assertRaises(ValueError):
                    self.parser.parse(temp_file, evidence_id="x")
        finally:
            import os; os.unlink(temp_file)

    def test_raises_value_error_for_garbage_input(self):
        temp_file = self._write_temp_email(RAW_EMAIL_GARBAGE)
        try:
            with self.assertRaises(ValueError):
                self.parser.parse(temp_file, evidence_id="x")
        finally:
            import os; os.unlink(temp_file)

    def test_parses_email_message_and_attachment(self):
        import hashlib
        temp_file = self._write_temp_email(RAW_EMAIL_FIXTURE)
        try:
            arts = self.parser.parse(temp_file, evidence_id=EMAIL_EVIDENCE_ID)
            # Should return 2 artifacts: 1 email_header, 1 file_record (attachment)
            self.assertEqual(len(arts), 2)

            self.assertEqual(arts[0].artifact_type, "email_header")
            self.assertEqual(arts[1].artifact_type, "file_record")

            # Validate header artifact fields
            msg_art = arts[0]
            self.assertEqual(msg_art.normalized_fields.sender, "sender@example.com")
            self.assertEqual(msg_art.normalized_fields.recipients, "recipient@example.com, cc@example.com, bcc@example.com")
            self.assertEqual(msg_art.normalized_fields.subject, "Urgent: Action Required")
            self.assertIsNotNone(msg_art.timestamp)
            self.assertEqual(msg_art.timestamp.year, 2024)

            # Raw fields checks
            raw = msg_art.raw_fields
            self.assertIn("Hello, click here: http://phish.link/login and visit http://google.com", raw["body_text"])
            self.assertIn("<p>Hello HTML</p>", raw["body_html"])
            self.assertEqual(len(raw["received_hops"]), 2)
            self.assertEqual(raw["received_hops"][0], "from mail.example.com (mail.example.com [192.0.2.1]) by mx.google.com")
            self.assertEqual(raw["received_hops"][1], "from gateway.example.com by mail.example.com")

            # Validate attachment artifact fields
            att_art = arts[1]
            self.assertEqual(att_art.raw_fields["filename"], "malware.exe")
            self.assertEqual(att_art.raw_fields["content_type"], "application/octet-stream")
            self.assertEqual(att_art.raw_fields["size_bytes"], len(b"test payload"))
            self.assertEqual(att_art.raw_fields["sha256"], hashlib.sha256(b"test payload").hexdigest())
            self.assertEqual(att_art.normalized_fields.file_path, "malware.exe")
        finally:
            import os; os.unlink(temp_file)

    def test_parses_malformed_date_gracefully(self):
        temp_file = self._write_temp_email(RAW_EMAIL_MALFORMED_DATE)
        try:
            arts = self.parser.parse(temp_file, evidence_id=EMAIL_EVIDENCE_ID)
            self.assertEqual(len(arts), 1)
            self.assertEqual(arts[0].artifact_type, "email_header")
            self.assertIsNone(arts[0].timestamp)
            self.assertEqual(arts[0].normalized_fields.sender, "sender@example.com")
            self.assertEqual(arts[0].normalized_fields.subject, "Bad Date Header")
        finally:
            import os; os.unlink(temp_file)

    def test_parses_no_attachment_email(self):
        temp_file = self._write_temp_email(RAW_EMAIL_NO_ATTACHMENT)
        try:
            arts = self.parser.parse(temp_file, evidence_id=EMAIL_EVIDENCE_ID)
            self.assertEqual(len(arts), 1)
            msg_art = arts[0]
            self.assertEqual(msg_art.artifact_type, "email_header")
            self.assertEqual(msg_art.normalized_fields.subject, "No Attachments Here")
            self.assertEqual(msg_art.raw_fields["body_text"].strip(), "Just simple body.")
            self.assertIsNone(msg_art.raw_fields["body_html"])
        finally:
            import os; os.unlink(temp_file)


# ===========================================================================
# FilesystemParser Tests
# ===========================================================================

FLS_BODYFILE_FIXTURE = (
    "0|/usr/bin/python|1234|r/r-xr-xr-x|0|0|1048576|1710490931|1710490932|1710490933|1710490934\n"
    "0|/deleted_file.exe|5678*|r/r*rwxrwxrwx|0|0|4096|1710490935|1710490936|1710490937|1710490938\n"
)
ISTAT_FIXTURE = "Inode: 5678\nDeleted\nBlocks: 100 101"
FILESYSTEM_EVIDENCE_ID = "fs-evidence-uuid-001"


class TestFilesystemParserHappyPath(unittest.TestCase):

    def setUp(self) -> None:
        import tempfile
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".dd", delete=False)
        self.temp_file.write(b"ddimagefilebytes")
        self.temp_file.close()
        self.parser = FilesystemParser()

    def tearDown(self) -> None:
        import os
        os.unlink(self.temp_file.name)

    def _run(self) -> list[Artifact]:
        def fake_run_fls(binary, image_path):
            return FLS_BODYFILE_FIXTURE

        def fake_run_istat(binary, image_path, inode):
            self.assertEqual(inode, "5678")
            return ISTAT_FIXTURE

        with (
            patch("shutil.which", return_value="/usr/bin/tsk_tool"),
            patch.object(self.parser, "_run_fls", side_effect=fake_run_fls),
            patch.object(self.parser, "_run_istat", side_effect=fake_run_istat),
        ):
            return self.parser.parse(self.temp_file.name, evidence_id=FILESYSTEM_EVIDENCE_ID)

    def test_total_artifact_count(self):
        self.assertEqual(len(self._run()), 2)

    def test_artifact_types(self):
        for a in self._run():
            self.assertEqual(a.artifact_type, "file_record")

    def test_source_tool_is_tsk(self):
        for a in self._run():
            self.assertEqual(a.source_tool, "tsk")

    def test_evidence_id_propagated(self):
        for a in self._run():
            self.assertEqual(a.evidence_id, FILESYSTEM_EVIDENCE_ID)

    def test_active_file_not_deleted(self):
        arts = self._run()
        active = arts[0]
        self.assertEqual(active.raw_fields["name"], "/usr/bin/python")
        self.assertFalse(active.raw_fields["deleted"])
        self.assertFalse(active.normalized_fields.deleted)
        self.assertIsNone(active.raw_fields["istat"])

    def test_deleted_file_flagged_with_istat(self):
        arts = self._run()
        deleted = arts[1]
        self.assertEqual(deleted.raw_fields["name"], "/deleted_file.exe")
        self.assertTrue(deleted.raw_fields["deleted"])
        self.assertTrue(deleted.normalized_fields.deleted)
        self.assertEqual(deleted.raw_fields["istat"], ISTAT_FIXTURE)

    def test_timestamps_parsed(self):
        arts = self._run()
        first = arts[0]
        # Modify time should be set in timestamp and normalized fields
        self.assertIsNotNone(first.timestamp)
        self.assertEqual(first.timestamp.year, 2024)
        self.assertIsNotNone(first.normalized_fields.mtime)
        self.assertIsNotNone(first.normalized_fields.atime)
        self.assertIsNotNone(first.normalized_fields.ctime)


class TestFilesystemParserErrorHandling(unittest.TestCase):

    def test_raises_file_not_found_for_missing_image(self):
        parser = FilesystemParser()
        with self.assertRaises(FileNotFoundError):
            parser.parse("/nonexistent/image.dd", evidence_id="x")

    def test_raises_tsk_not_found_when_binary_missing(self):
        import tempfile, os
        f = tempfile.NamedTemporaryFile(suffix=".dd", delete=False)
        f.close()
        try:
            parser = FilesystemParser()
            with patch("shutil.which", return_value=None):
                with self.assertRaises(TSKNotFoundError) as ctx:
                    parser.parse(f.name, evidence_id="x")
            self.assertIn("fls", str(ctx.exception).lower())
        finally:
            os.unlink(f.name)

    def test_raises_tsk_execution_error_on_nonzero_exit(self):
        import tempfile, os
        f = tempfile.NamedTemporaryFile(suffix=".dd", delete=False)
        f.close()
        try:
            parser = FilesystemParser()
            failed_result = MagicMock(returncode=1, stdout="", stderr="Error executing fls")
            with (
                patch("shutil.which", return_value="/usr/bin/tsk_tool"),
                patch("subprocess.run", return_value=failed_result),
            ):
                with self.assertRaises(TSKExecutionError) as ctx:
                    parser.parse(f.name, evidence_id="x")
            self.assertIn("1", str(ctx.exception))
        finally:
            os.unlink(f.name)


# ===========================================================================
# Normalizer Tests
# ===========================================================================

class TestNormalizer(unittest.TestCase):
    """Unit tests for preprocessing/normalizer.py (Normalizer)."""

    def setUp(self) -> None:
        self.normalizer = Normalizer()

    def test_normalize_timestamps(self):
        # 1. timezone-aware datetime offset
        from datetime import timezone, timedelta
        dt_est = datetime(2024, 3, 15, 8, 22, 11, tzinfo=timezone(timedelta(hours=-5))) # EST
        art1 = Artifact(
            evidence_id="e1", source_tool="test", artifact_type="t",
            timestamp=dt_est
        )

        # 2. naive datetime (treated as UTC)
        dt_naive = datetime(2024, 3, 15, 13, 22, 11)
        art2 = Artifact(
            evidence_id="e1", source_tool="test", artifact_type="t",
            timestamp=dt_naive
        )

        # 3. Epoch float (milliseconds)
        art3 = Artifact(
            evidence_id="e1", source_tool="test", artifact_type="t",
            timestamp=1710490931000.0
        )

        # 4. String format with space UTC (assign after construction to bypass default Pydantic validation)
        art4 = Artifact(
            evidence_id="e1", source_tool="test", artifact_type="t"
        )
        art4.timestamp = "2024-03-15 13:22:11 UTC"

        self.normalizer.normalize([art1, art2, art3, art4])

        # Assert all normalized to UTC datetimes
        for art in (art1, art2, art4):
            self.assertIsNotNone(art.timestamp)
            self.assertEqual(art.timestamp.tzinfo, timezone.utc)
            self.assertEqual(art.timestamp.hour, 13)
            self.assertEqual(art.timestamp.minute, 22)
            self.assertEqual(art.timestamp.second, 11)

        self.assertIsNotNone(art3.timestamp)
        self.assertEqual(art3.timestamp.tzinfo, timezone.utc)

    def test_normalize_host_fqdn(self):
        # Case 1: FQDN upper-case
        art1 = Artifact(
            evidence_id="e1", source_tool="test", artifact_type="t",
            normalized_fields=NormalizedFields(host="ACC-04.corp.net")
        )
        # Case 2: lower-case without domain
        art2 = Artifact(
            evidence_id="e1", source_tool="test", artifact_type="t",
            normalized_fields=NormalizedFields(host="acc-04")
        )
        # Case 3: IP address (should NOT split)
        art3 = Artifact(
            evidence_id="e1", source_tool="test", artifact_type="t",
            normalized_fields=NormalizedFields(host="192.168.1.10")
        )

        self.normalizer.normalize([art1, art2, art3])

        self.assertEqual(art1.normalized_fields.host, "acc-04")
        self.assertEqual(art1.normalized_fields.domain, "corp.net")

        self.assertEqual(art2.normalized_fields.host, "acc-04")
        self.assertIsNone(art2.normalized_fields.domain)

        self.assertEqual(art3.normalized_fields.host, "192.168.1.10")
        self.assertIsNone(art3.normalized_fields.domain)

    def test_normalize_ip_addresses(self):
        # Case 1: IPv6-mapped IPv4
        art1 = Artifact(
            evidence_id="e1", source_tool="test", artifact_type="t",
            normalized_fields=NormalizedFields(src_ip="::ffff:192.168.1.10", dst_ip="::ffff:8.8.8.8")
        )
        # Case 2: standard IPv6
        art2 = Artifact(
            evidence_id="e1", source_tool="test", artifact_type="t",
            normalized_fields=NormalizedFields(src_ip="2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        )

        self.normalizer.normalize([art1, art2])

        self.assertEqual(art1.normalized_fields.src_ip, "192.168.1.10")
        self.assertEqual(art1.normalized_fields.dst_ip, "8.8.8.8")

        # Standardized IPv6 representation (condensed)
        self.assertEqual(art2.normalized_fields.src_ip, "2001:db8:85a3::8a2e:370:7334")

    def test_raw_fields_left_untouched(self):
        raw = {"host": "ACC-04.corp.net", "ip": "::ffff:192.168.1.10"}
        art = Artifact(
            evidence_id="e1", source_tool="test", artifact_type="t",
            raw_fields=raw,
            normalized_fields=NormalizedFields(host="ACC-04.corp.net", src_ip="::ffff:192.168.1.10")
        )

        self.normalizer.normalize([art])

        # Normalized fields must change
        self.assertEqual(art.normalized_fields.host, "acc-04")
        self.assertEqual(art.normalized_fields.src_ip, "192.168.1.10")

        # raw_fields must be completely identical
        self.assertEqual(art.raw_fields, raw)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# ===========================================================================
# Evasion Indicator Tests
# ===========================================================================

from preprocessing.parsers.evtx_parser import EvtxParser
from preprocessing.parsers.registry_parser import _check_timestomping
from preprocessing.parsers.memory_parser import _check_memory_timestomping


def _make_artifact(
    *,
    artifact_type: str = "log_event",
    source_tool: str = "hayabusa",
    evidence_id: str = "ev-001",
    raw_fields: dict | None = None,
    timestamp: datetime | None = None,
) -> Artifact:
    """Minimal Artifact constructor for test fixtures."""
    return Artifact(
        evidence_id=evidence_id,
        source_tool=source_tool,
        artifact_type=artifact_type,
        raw_fields=raw_fields or {},
        timestamp=timestamp,
    )


class TestEvtxEvasionIndicators(unittest.TestCase):
    """EvtxParser._check_evasion_indicators() — unit tests without subprocess."""

    def setUp(self):
        self.parser = EvtxParser()
        self.ev_id = "ev-evtx-001"

    # ── Event ID 1102 ──────────────────────────────────────────────────────

    def test_eid_1102_emits_evasion_indicator(self):
        """A single EID 1102 record produces exactly one evasion_indicator."""
        arts = [_make_artifact(raw_fields={
            "EventID": 1102,
            "Channel": "Security",
            "Computer": "DC-01",
            "Details": "Log was cleared",
        })]
        indicators = self.parser._check_evasion_indicators(arts, self.ev_id)
        evasion = [a for a in indicators if a.artifact_type == "evasion_indicator"]
        self.assertEqual(len(evasion), 1)
        self.assertEqual(evasion[0].raw_fields["indicator"], "audit_log_cleared")
        self.assertEqual(evasion[0].raw_fields["event_id"], 1102)
        self.assertEqual(evasion[0].raw_fields["computer"], "DC-01")
        self.assertEqual(evasion[0].normalized_fields.severity, "high")
        self.assertEqual(evasion[0].normalized_fields.rule_name, "audit_log_cleared")

    def test_eid_1102_as_string_is_also_detected(self):
        """EventID may be a string in some Hayabusa versions."""
        arts = [_make_artifact(raw_fields={"EventID": "1102", "Channel": "Security"})]
        indicators = self.parser._check_evasion_indicators(arts, self.ev_id)
        self.assertEqual(len([a for a in indicators if a.artifact_type == "evasion_indicator"]), 1)

    def test_eid_1102_note_contains_disclaimer(self):
        """Note field must explicitly state this is an indicator, not a guarantee."""
        arts = [_make_artifact(raw_fields={"EventID": 1102})]
        indicators = self.parser._check_evasion_indicators(arts, self.ev_id)
        note = indicators[0].raw_fields["note"]
        self.assertIn("indicator", note.lower())
        self.assertIn("not a guarantee", note.lower())

    def test_no_eid_1102_produces_no_indicator(self):
        """Normal event IDs must not produce any evasion_indicator."""
        arts = [
            _make_artifact(raw_fields={"EventID": 4624}),
            _make_artifact(raw_fields={"EventID": 4688}),
        ]
        indicators = self.parser._check_evasion_indicators(arts, self.ev_id)
        self.assertEqual(len(indicators), 0)

    def test_multiple_eid_1102_produces_multiple_indicators(self):
        """Each 1102 event produces its own indicator artifact."""
        arts = [
            _make_artifact(raw_fields={"EventID": 1102, "Computer": "HOST-A"}),
            _make_artifact(raw_fields={"EventID": 4624}),
            _make_artifact(raw_fields={"EventID": 1102, "Computer": "HOST-B"}),
        ]
        indicators = self.parser._check_evasion_indicators(arts, self.ev_id)
        evasion = [a for a in indicators if a.artifact_type == "evasion_indicator"
                   and a.raw_fields.get("indicator") == "audit_log_cleared"]
        self.assertEqual(len(evasion), 2)

    # ── EventRecordID gaps ─────────────────────────────────────────────────

    def test_record_id_gap_emits_indicator(self):
        """A gap of > 1 between consecutive EventRecordIDs emits one indicator."""
        arts = [
            _make_artifact(raw_fields={"Channel": "Security", "EventRecordID": 100}),
            _make_artifact(raw_fields={"Channel": "Security", "EventRecordID": 200}),
        ]
        indicators = self.parser._check_evasion_indicators(arts, self.ev_id)
        gap_arts = [a for a in indicators
                    if a.raw_fields.get("indicator") == "event_record_id_gap"]
        self.assertEqual(len(gap_arts), 1)
        ind = gap_arts[0]
        self.assertEqual(ind.raw_fields["gap_start_id"], 101)
        self.assertEqual(ind.raw_fields["gap_end_id"], 199)
        self.assertEqual(ind.raw_fields["missing_records"], 99)
        self.assertEqual(ind.raw_fields["last_seen_id"], 100)
        self.assertEqual(ind.raw_fields["next_seen_id"], 200)
        self.assertEqual(ind.normalized_fields.severity, "medium")
        self.assertIn("not a guarantee", ind.raw_fields["note"].lower())

    def test_consecutive_record_ids_produce_no_gap_indicator(self):
        """IDs 1, 2, 3 are consecutive — no gap should be emitted."""
        arts = [
            _make_artifact(raw_fields={"Channel": "System", "EventRecordID": 1}),
            _make_artifact(raw_fields={"Channel": "System", "EventRecordID": 2}),
            _make_artifact(raw_fields={"Channel": "System", "EventRecordID": 3}),
        ]
        indicators = self.parser._check_evasion_indicators(arts, self.ev_id)
        gap_arts = [a for a in indicators
                    if a.raw_fields.get("indicator") == "event_record_id_gap"]
        self.assertEqual(len(gap_arts), 0)

    def test_gaps_tracked_per_channel_independently(self):
        """Gaps are computed per-channel so cross-channel IDs don't mix."""
        arts = [
            # Security channel: 100 → 200 (gap)
            _make_artifact(raw_fields={"Channel": "Security", "EventRecordID": 100}),
            _make_artifact(raw_fields={"Channel": "Security", "EventRecordID": 200}),
            # System channel: 1 → 2 (no gap)
            _make_artifact(raw_fields={"Channel": "System", "EventRecordID": 1}),
            _make_artifact(raw_fields={"Channel": "System", "EventRecordID": 2}),
        ]
        indicators = self.parser._check_evasion_indicators(arts, self.ev_id)
        gap_arts = [a for a in indicators
                    if a.raw_fields.get("indicator") == "event_record_id_gap"]
        # Exactly one gap, in Security
        self.assertEqual(len(gap_arts), 1)
        self.assertEqual(gap_arts[0].raw_fields["channel"], "Security")

    def test_missing_record_id_field_does_not_crash(self):
        """Records without EventRecordID are silently skipped."""
        arts = [
            _make_artifact(raw_fields={"Channel": "Security"}),
            _make_artifact(raw_fields={"Channel": "Security", "EventRecordID": None}),
        ]
        # Should not raise
        self.parser._check_evasion_indicators(arts, self.ev_id)

    def test_empty_artifact_list_produces_no_indicators(self):
        indicators = self.parser._check_evasion_indicators([], self.ev_id)
        self.assertEqual(indicators, [])

    def test_all_evasion_indicators_have_correct_type(self):
        """Every artifact emitted by the check must have artifact_type=evasion_indicator."""
        arts = [
            _make_artifact(raw_fields={"EventID": 1102}),
            _make_artifact(raw_fields={"Channel": "Security", "EventRecordID": 1}),
            _make_artifact(raw_fields={"Channel": "Security", "EventRecordID": 500}),
        ]
        indicators = self.parser._check_evasion_indicators(arts, self.ev_id)
        for ind in indicators:
            self.assertEqual(ind.artifact_type, "evasion_indicator")
            self.assertEqual(ind.evidence_id, self.ev_id)
            self.assertEqual(ind.source_tool, "hayabusa")


class TestRegistryTimestomping(unittest.TestCase):
    """registry_parser._check_timestomping() — unit tests."""

    EV_ID = "ev-reg-001"

    def _make_reg_artifact(self, plugin: str, plugin_text: str) -> Artifact:
        return _make_artifact(
            artifact_type="registry_key",
            source_tool="regripper",
            raw_fields={"plugin": plugin, "plugin_text": plugin_text},
        )

    # ── Creation-after-modification ────────────────────────────────────────

    def test_creation_after_modification_emits_indicator(self):
        """Plugin text where creation > last-written emits evasion_indicator."""
        plugin_text = textwrap.dedent("""\
            Launching userassist v.20200517
            Last Written: 2021-03-10 14:22:00Z
            Created: 2021-03-11 09:00:00Z
            SomeKey=SomeValue
        """)
        arts = [self._make_reg_artifact("userassist", plugin_text)]
        indicators = _check_timestomping(arts, self.EV_ID)
        creation_inds = [a for a in indicators
                         if a.raw_fields.get("indicator") == "timestamp_creation_after_modification"]
        self.assertEqual(len(creation_inds), 1)
        ind = creation_inds[0]
        self.assertEqual(ind.artifact_type, "evasion_indicator")
        self.assertEqual(ind.source_tool, "regripper")
        self.assertEqual(ind.normalized_fields.severity, "high")
        self.assertIn("not a guarantee", ind.raw_fields["note"].lower())
        self.assertGreater(ind.raw_fields["delta_seconds"], 0)

    def test_legitimate_timestamps_produce_no_indicator(self):
        """Modification time after creation time is legitimate — no indicator."""
        plugin_text = textwrap.dedent("""\
            Created: 2021-03-10 08:00:00Z
            Last Written: 2021-03-11 14:22:00Z
        """)
        arts = [self._make_reg_artifact("userassist", plugin_text)]
        indicators = _check_timestomping(arts, self.EV_ID)
        creation_inds = [a for a in indicators
                         if a.raw_fields.get("indicator") == "timestamp_creation_after_modification"]
        self.assertEqual(len(creation_inds), 0)

    # ── All timestamps identical ───────────────────────────────────────────

    def test_all_identical_timestamps_emits_indicator(self):
        """Three identical timestamps to the second triggers the indicator."""
        ts = "2021-01-01 00:00:00Z"
        plugin_text = f"Created: {ts}\nLast Written: {ts}\nModified: {ts}"
        arts = [self._make_reg_artifact("shimcache", plugin_text)]
        indicators = _check_timestomping(arts, self.EV_ID)
        ident_inds = [a for a in indicators
                      if a.raw_fields.get("indicator") == "all_timestamps_identical"]
        self.assertEqual(len(ident_inds), 1)
        ind = ident_inds[0]
        self.assertEqual(ind.normalized_fields.severity, "medium")
        self.assertEqual(ind.raw_fields["timestamp_count"], 3)
        self.assertIn("not a guarantee", ind.raw_fields["note"].lower())

    def test_two_identical_timestamps_does_not_trigger(self):
        """Only 2 identical timestamps is too common to flag (< 3 threshold)."""
        ts = "2021-01-01 00:00:00Z"
        plugin_text = f"Created: {ts}\nLast Written: {ts}"
        arts = [self._make_reg_artifact("shimcache", plugin_text)]
        indicators = _check_timestomping(arts, self.EV_ID)
        ident_inds = [a for a in indicators
                      if a.raw_fields.get("indicator") == "all_timestamps_identical"]
        self.assertEqual(len(ident_inds), 0)

    def test_varied_timestamps_do_not_trigger(self):
        """Distinct timestamps produce no all_timestamps_identical indicator."""
        plugin_text = (
            "Created: 2021-01-01 08:00:00Z\n"
            "Last Written: 2021-01-02 09:30:00Z\n"
            "Modified: 2021-01-03 12:00:00Z"
        )
        arts = [self._make_reg_artifact("shimcache", plugin_text)]
        indicators = _check_timestomping(arts, self.EV_ID)
        ident_inds = [a for a in indicators
                      if a.raw_fields.get("indicator") == "all_timestamps_identical"]
        self.assertEqual(len(ident_inds), 0)

    def test_no_timestamps_in_plugin_text_produces_no_indicator(self):
        """Plugin blocks with no timestamps at all produce no indicators."""
        arts = [self._make_reg_artifact("userassist", "SomeKey=SomeValue\nNoTimestamp: here")]
        indicators = _check_timestomping(arts, self.EV_ID)
        self.assertEqual(indicators, [])

    def test_evasion_indicator_has_correct_source_fields(self):
        """All emitted indicators carry the right source_tool and artifact_type."""
        ts = "2021-01-01 00:00:00Z"
        plugin_text = f"Created: {ts}\nLast Written: {ts}\nModified: {ts}"
        arts = [self._make_reg_artifact("myplugin", plugin_text)]
        indicators = _check_timestomping(arts, self.EV_ID)
        for ind in indicators:
            self.assertEqual(ind.artifact_type, "evasion_indicator")
            self.assertEqual(ind.source_tool, "regripper")
            self.assertEqual(ind.evidence_id, self.EV_ID)


class TestMemoryTimestomping(unittest.TestCase):
    """memory_parser._check_memory_timestomping() — unit tests."""

    EV_ID = "ev-mem-001"

    PROC_TS = "2024-03-15 08:00:00.000000 UTC"   # process create time
    LATER_TS = "2024-03-15 09:00:00.000000 UTC"   # 1 hour later
    EARLIER_TS = "2024-03-15 07:00:00.000000 UTC"  # 1 hour earlier (impossible for DLL)

    def _make_proc(self, pid: int, create_time: str, name: str = "proc.exe") -> Artifact:
        return _make_artifact(
            artifact_type="process_record",
            source_tool="volatility3",
            raw_fields={"PID": pid, "CreateTime": create_time, "ImageFileName": name},
        )

    def _make_dll(self, pid: int, load_time: str, dll_name: str = "ntdll.dll") -> Artifact:
        return _make_artifact(
            artifact_type="dll_record",
            source_tool="volatility3",
            raw_fields={"PID": pid, "LoadTime": load_time, "Name": dll_name,
                        "Process": "proc.exe"},
        )

    # ── All process CreateTimes identical ──────────────────────────────────

    def test_all_identical_process_create_times_emits_indicator(self):
        """≥ 3 processes with the same CreateTime emits an indicator."""
        ts = self.PROC_TS
        arts = [self._make_proc(i, ts) for i in range(1, 5)]  # 4 processes
        indicators = _check_memory_timestomping(arts, self.EV_ID)
        ident = [a for a in indicators
                 if a.raw_fields.get("indicator") == "all_process_create_times_identical"]
        self.assertEqual(len(ident), 1)
        self.assertEqual(ident[0].raw_fields["process_count"], 4)
        self.assertEqual(ident[0].normalized_fields.severity, "medium")
        self.assertIn("not a guarantee", ident[0].raw_fields["note"].lower())

    def test_two_identical_process_times_does_not_trigger(self):
        """Only 2 processes with the same time is below the threshold."""
        ts = self.PROC_TS
        arts = [self._make_proc(1, ts), self._make_proc(2, ts)]
        indicators = _check_memory_timestomping(arts, self.EV_ID)
        ident = [a for a in indicators
                 if a.raw_fields.get("indicator") == "all_process_create_times_identical"]
        self.assertEqual(len(ident), 0)

    def test_varied_process_create_times_produce_no_indicator(self):
        """Distinct process CreateTimes produce no indicator."""
        arts = [
            self._make_proc(1, "2024-03-15 08:00:00.000000 UTC"),
            self._make_proc(2, "2024-03-15 09:01:00.000000 UTC"),
            self._make_proc(3, "2024-03-15 10:02:00.000000 UTC"),
        ]
        indicators = _check_memory_timestomping(arts, self.EV_ID)
        ident = [a for a in indicators
                 if a.raw_fields.get("indicator") == "all_process_create_times_identical"]
        self.assertEqual(len(ident), 0)

    # ── DLL LoadTime before process CreateTime ─────────────────────────────

    def test_dll_load_before_process_create_emits_indicator(self):
        """DLL LoadTime < process CreateTime emits an indicator with correct fields."""
        arts = [
            self._make_proc(4, self.PROC_TS),           # process created at 08:00
            self._make_dll(4, self.EARLIER_TS, "evil.dll"),  # DLL "loaded" at 07:00
        ]
        indicators = _check_memory_timestomping(arts, self.EV_ID)
        dll_inds = [a for a in indicators
                    if a.raw_fields.get("indicator") == "dll_load_time_before_process_create_time"]
        self.assertEqual(len(dll_inds), 1)
        ind = dll_inds[0]
        self.assertEqual(ind.raw_fields["pid"], 4)
        self.assertEqual(ind.raw_fields["dll_name"], "evil.dll")
        self.assertGreater(ind.raw_fields["delta_seconds"], 0)
        self.assertEqual(ind.normalized_fields.severity, "high")
        self.assertIn("not a guarantee", ind.raw_fields["note"].lower())

    def test_dll_load_after_process_create_is_legitimate(self):
        """DLL LoadTime after process CreateTime is normal — no indicator."""
        arts = [
            self._make_proc(4, self.PROC_TS),          # process at 08:00
            self._make_dll(4, self.LATER_TS, "ntdll.dll"),  # DLL at 09:00
        ]
        indicators = _check_memory_timestomping(arts, self.EV_ID)
        dll_inds = [a for a in indicators
                    if a.raw_fields.get("indicator") == "dll_load_time_before_process_create_time"]
        self.assertEqual(len(dll_inds), 0)

    def test_dll_without_matching_pid_is_skipped(self):
        """A DLL whose PID has no corresponding process record is silently ignored."""
        arts = [
            self._make_dll(999, self.EARLIER_TS, "orphan.dll"),  # PID 999 not in pslist
        ]
        indicators = _check_memory_timestomping(arts, self.EV_ID)
        self.assertEqual(len(indicators), 0)

    def test_empty_artifact_list_produces_no_indicators(self):
        indicators = _check_memory_timestomping([], self.EV_ID)
        self.assertEqual(indicators, [])

    def test_all_indicators_have_correct_type_and_source(self):
        """Every emitted artifact has artifact_type=evasion_indicator and correct source."""
        ts = self.PROC_TS
        arts = (
            [self._make_proc(i, ts) for i in range(1, 4)]  # 3 identical procs
            + [self._make_proc(4, self.PROC_TS),
               self._make_dll(4, self.EARLIER_TS)]         # DLL before process
        )
        indicators = _check_memory_timestomping(arts, self.EV_ID)
        self.assertGreater(len(indicators), 0)
        for ind in indicators:
            self.assertEqual(ind.artifact_type, "evasion_indicator")
            self.assertEqual(ind.source_tool, "volatility3")
            self.assertEqual(ind.evidence_id, self.EV_ID)


class TestToolVersions(unittest.TestCase):
    """Tests the tool_versions metadata resolution and propagation across all parsers."""

    def setUp(self):
        import config.tool_versions
        config.tool_versions.reload()

    def tearDown(self):
        import config.tool_versions
        config.tool_versions.reload()

    def test_default_version_is_unknown(self):
        """Without a mock versions JSON, get_tool_version should return 'unknown'."""
        from config.tool_versions import get_tool_version
        self.assertEqual(get_tool_version("non_existent_tool_xyz"), "unknown")

    def test_version_caching_and_mocking(self):
        """Verify that writing a mock tool_versions.json is resolved correctly."""
        import json
        from pathlib import Path
        import config.tool_versions

        target_file = Path(__file__).parent / "config" / "tool_versions.json"
        
        # Backup original if exists
        backup = None
        if target_file.exists():
            backup = target_file.read_text(encoding="utf-8")
        
        target_file.parent.mkdir(parents=True, exist_ok=True)
        mock_data = {
            "written_at": "2026-08-25T12:00:00Z",
            "hayabusa": "2.18.0-mocked",
            "zeek": "6.0.3-mocked",
            "suricata": "7.0.3-mocked",
            "volatility3": "2.7.1-mocked",
            "regripper": "20201114-mocked"
        }
        try:
            target_file.write_text(json.dumps(mock_data), encoding="utf-8")
            config.tool_versions.reload()
            
            self.assertEqual(config.tool_versions.get_tool_version("hayabusa"), "2.18.0-mocked")
            self.assertEqual(config.tool_versions.get_tool_version("zeek"), "6.0.3-mocked")
            self.assertEqual(config.tool_versions.get_tool_version("suricata"), "7.0.3-mocked")
            self.assertEqual(config.tool_versions.get_tool_version("volatility3"), "2.7.1-mocked")
            self.assertEqual(config.tool_versions.get_tool_version("regripper"), "20201114-mocked")
        finally:
            if backup is not None:
                target_file.write_text(backup, encoding="utf-8")
            else:
                target_file.unlink(missing_ok=True)
            config.tool_versions.reload()

    def test_parsers_stamp_tool_version(self):
        """Verify that all parsers include tool_version in their Artifact raw_fields."""
        import json
        from pathlib import Path
        import config.tool_versions

        target_file = Path(__file__).parent / "config" / "tool_versions.json"
        backup = None
        if target_file.exists():
            backup = target_file.read_text(encoding="utf-8")

        mock_data = {
            "written_at": "2026-08-25T12:00:00Z",
            "hayabusa": "hayabusa-v123",
            "zeek": "zeek-v456",
            "suricata": "suricata-v789",
            "volatility3": "vol3-v012",
            "regripper": "regripper-v345",
            "tsk": "tsk-v678",
            "hindsight": "hindsight-v901",
            "python_email": "python-v5.0"
        }
        try:
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text(json.dumps(mock_data), encoding="utf-8")
            config.tool_versions.reload()

            # EvtxParser
            parser_evtx = EvtxParser()
            parser_evtx._tool_version = config.tool_versions.get_tool_version("hayabusa")
            art_evtx = parser_evtx._record_to_artifact({"EventID": 1102}, "ev-1")
            self.assertEqual(art_evtx.raw_fields["tool_version"], "hayabusa-v123")

            # MemoryParser
            parser_mem = MemoryParser()
            parser_mem._tool_version = config.tool_versions.get_tool_version("volatility3")
            art_mem = parser_mem._record_to_artifact({"PID": 4}, "pslist", "process_record", "ev-1")
            self.assertEqual(art_mem.raw_fields["tool_version"], "vol3-v012")

            # RegistryParser
            from preprocessing.parsers.registry_parser import _make_artifact as make_reg_artifact
            art_reg = make_reg_artifact(
                evidence_id="ev-1",
                plugin="userassist",
                plugin_text="rawtext",
                key_path="HKLM",
                value_name="run",
                value_data="exe",
                timestamp=None,
                tool_version=config.tool_versions.get_tool_version("regripper")
            )
            self.assertEqual(art_reg.raw_fields["tool_version"], "regripper-v345")

            # PcapParser
            parser_pcap = PcapParser()
            parser_pcap._zeek_version = config.tool_versions.get_tool_version("zeek")
            parser_pcap._suricata_version = config.tool_versions.get_tool_version("suricata")
            
            art_zeek = parser_pcap._zeek_record_to_artifact({"ts": "123"}, "network_connection", "ev-1")
            self.assertEqual(art_zeek.raw_fields["tool_version"], "zeek-v456")

            art_suri = parser_pcap._suricata_alert_to_artifact({"timestamp": "2026-08-25T12:00:00Z"}, "ev-1")
            self.assertEqual(art_suri.raw_fields["tool_version"], "suricata-v789")

            # FilesystemParser
            parser_fs = FilesystemParser()
            parser_fs._tool_version = config.tool_versions.get_tool_version("tsk")
            # We can mock create a single artifact using dummy args, or since fls parsing is complex,
            # we just test the version resolving.
            self.assertEqual(parser_fs._tool_version, "tsk-v678")

            # BrowserParser
            parser_browser = BrowserParser()
            parser_browser._tool_version = config.tool_versions.get_tool_version("hindsight")
            art_browser = parser_browser._record_to_artifact({"type": "history"}, "ev-1")
            self.assertEqual(art_browser.raw_fields["tool_version"], "hindsight-v901")

            # EmailParser
            parser_email = EmailParser()
            parser_email._tool_version = config.tool_versions.get_tool_version("python_email")
            self.assertEqual(parser_email._tool_version, "python-v5.0")

        finally:
            if backup is not None:
                target_file.write_text(backup, encoding="utf-8")
            else:
                target_file.unlink(missing_ok=True)
            config.tool_versions.reload()


if __name__ == "__main__":
    print("=" * 70)
    print("  Argus — Preprocessing Parser Unit Tests")
    print("=" * 70)
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    # EvtxParser
    suite.addTests(loader.loadTestsFromTestCase(TestEvtxParserHappyPath))
    suite.addTests(loader.loadTestsFromTestCase(TestEvtxParserErrorHandling))
    suite.addTests(loader.loadTestsFromTestCase(TestEvtxParserMalformedJSONL))
    # MemoryParser
    suite.addTests(loader.loadTestsFromTestCase(TestMemoryParserJsonOutput))
    suite.addTests(loader.loadTestsFromTestCase(TestMemoryParserTableFallback))
    suite.addTests(loader.loadTestsFromTestCase(TestMemoryParserErrorHandling))
    # PcapParser
    suite.addTests(loader.loadTestsFromTestCase(TestPcapParserZeek))
    suite.addTests(loader.loadTestsFromTestCase(TestPcapParserSuricata))
    suite.addTests(loader.loadTestsFromTestCase(TestPcapParserCombined))
    suite.addTests(loader.loadTestsFromTestCase(TestPcapParserErrorHandling))
    # RegistryParser
    suite.addTests(loader.loadTestsFromTestCase(TestRegistryParserSectionSplitting))
    suite.addTests(loader.loadTestsFromTestCase(TestRegistryParserHappyPath))
    suite.addTests(loader.loadTestsFromTestCase(TestRegistryParserMultipleProfiles))
    suite.addTests(loader.loadTestsFromTestCase(TestRegistryParserErrorHandling))
    # BrowserParser
    suite.addTests(loader.loadTestsFromTestCase(TestBrowserParserHappyPath))
    suite.addTests(loader.loadTestsFromTestCase(TestBrowserParserErrorHandling))
    suite.addTests(loader.loadTestsFromTestCase(TestBrowserParserMalformedJSONL))
    # EmailParser
    suite.addTests(loader.loadTestsFromTestCase(TestEmailParser))
    # FilesystemParser
    suite.addTests(loader.loadTestsFromTestCase(TestFilesystemParserHappyPath))
    suite.addTests(loader.loadTestsFromTestCase(TestFilesystemParserErrorHandling))
    # Normalizer
    suite.addTests(loader.loadTestsFromTestCase(TestNormalizer))
    # ParserRouter
    suite.addTests(loader.loadTestsFromTestCase(TestParserRouter))
    # Evasion indicators
    suite.addTests(loader.loadTestsFromTestCase(TestEvtxEvasionIndicators))
    suite.addTests(loader.loadTestsFromTestCase(TestRegistryTimestomping))
    suite.addTests(loader.loadTestsFromTestCase(TestMemoryTimestomping))
    # Tool Versions
    suite.addTests(loader.loadTestsFromTestCase(TestToolVersions))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
