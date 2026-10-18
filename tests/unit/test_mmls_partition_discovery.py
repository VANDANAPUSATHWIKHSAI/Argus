"""
Regression and unit tests for mmls partition discovery and fls -o propagation.

Verifies:
- Automatic partition-table discovery using mmls for disk images (e.g. E01 / raw DD).
- Correct sector-offset selection and propagation to fls -o.
- Explicit filtering of unallocated regions, GPT headers, meta slots, and reserved partitions.
- Fallback to unpartitioned mode if mmls fails, times out, or is missing.
- Retention of evidence ID, file provenance, and partition offset in parsed artifacts.
"""

import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from preprocessing.parsers.filesystem_parser import FilesystemParser, TSKNotFoundError, TSKExecutionError


# Synthetic SleuthKit mmls output for standard DOS/MBR disk
SYNTHETIC_MMLS_MBR_OUTPUT = """
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
003:  -------   0000206848   0000208895   0000002048   Unallocated
004:  000:001   0000208896   0001023999   0000815104   Linux (0x83)
005:  -------   0001024000   0001048575   0000024576   Unallocated
"""

# Synthetic SleuthKit mmls output for GUID Partition Table (GPT)
SYNTHETIC_MMLS_GPT_OUTPUT = """
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000001   0000000033   0000000033   GPT Header
002:  -------   0000000034   0000002047   0000002014   Unallocated
003:  000       0000002048   0000616447   0000614400   EFI System Partition
004:  001       0000616448   0000649215   0000032768   Microsoft Reserved Partition
005:  002       0000649216   0004194303   0003545088   Basic Data Partition
006:  -------   0004194304   0004194337   0000000034   Unallocated
"""

SYNTHETIC_BODYFILE_DATA = (
    "0|/evil_script.ps1|1024|r/rrwxrwxrwx|0|0|512|1697500800|1697500800|1697500800|1697500800\n"
    "0|/Windows/System32/cmd.exe|2048|r/rrwxr-xr-x|0|0|300000|1697500800|1697500800|1697500800|1697500800\n"
)


class TestMMLSPartitionDiscovery(unittest.TestCase):

    def setUp(self):
        self.parser = FilesystemParser()
        self.dummy_image = Path("dummy_disk.e01")

    @patch("shutil.which", return_value="/usr/bin/mmls")
    @patch("subprocess.run")
    def test_discover_mbr_partitions(self, mock_subproc, mock_which):
        """Verifies sector offsets 2048 and 208896 are discovered and unallocated/meta are skipped."""
        mock_subproc.return_value = MagicMock(returncode=0, stdout=SYNTHETIC_MMLS_MBR_OUTPUT, stderr="")

        offsets = self.parser._discover_partition_offsets(self.dummy_image)

        self.assertEqual(offsets, ["2048", "208896"])
        mock_subproc.assert_called_once()
        cmd_called = mock_subproc.call_args[0][0]
        self.assertEqual(cmd_called[0], "/usr/bin/mmls")
        self.assertEqual(cmd_called[1], str(self.dummy_image))

    @patch("shutil.which", return_value="/usr/bin/mmls")
    @patch("subprocess.run")
    def test_discover_gpt_partitions_filters_reserved_and_headers(self, mock_subproc, mock_which):
        """Verifies that GPT Header, Safety Table, and Microsoft Reserved Partition are excluded."""
        mock_subproc.return_value = MagicMock(returncode=0, stdout=SYNTHETIC_MMLS_GPT_OUTPUT, stderr="")

        offsets = self.parser._discover_partition_offsets(self.dummy_image)

        # Slot 003 (EFI System Partition, 2048) and Slot 005 (Basic Data Partition, 649216)
        self.assertEqual(offsets, ["2048", "649216"])

    @patch("shutil.which", return_value="/usr/bin/mmls")
    @patch("subprocess.run")
    def test_mmls_nonzero_exit_falls_back_to_unpartitioned(self, mock_subproc, mock_which):
        """Verifies that if mmls exits with error (e.g. raw single volume), fallback is [None]."""
        mock_subproc.return_value = MagicMock(returncode=1, stdout="", stderr="Cannot determine partition type")

        offsets = self.parser._discover_partition_offsets(self.dummy_image)

        self.assertEqual(offsets, [None])

    @patch("shutil.which", return_value="/usr/bin/mmls")
    @patch("subprocess.run")
    def test_mmls_timeout_falls_back_gracefully(self, mock_subproc, mock_which):
        """Verifies subprocess timeout falls back safely without unhandled exception."""
        mock_subproc.side_effect = subprocess.TimeoutExpired(cmd=["mmls"], timeout=30)

        offsets = self.parser._discover_partition_offsets(self.dummy_image)

        self.assertEqual(offsets, [None])

    @patch("shutil.which", return_value=None)
    def test_mmls_binary_not_found_falls_back(self, mock_which):
        """Verifies that if mmls is absent, fallback to [None] is returned."""
        with patch.object(self.parser, "_find_binary", side_effect=TSKNotFoundError("mmls missing")):
            offsets = self.parser._discover_partition_offsets(self.dummy_image)
            self.assertEqual(offsets, [None])

    @patch("subprocess.run")
    def test_run_fls_propagates_offset_argument(self, mock_subproc):
        """Verifies that -o <offset> argument is correctly passed to fls command."""
        mock_subproc.return_value = MagicMock(returncode=0, stdout="test stdout", stderr="")

        stdout = self.parser._run_fls("/usr/bin/fls", self.dummy_image, offset="2048")

        self.assertEqual(stdout, "test stdout")
        cmd_called = mock_subproc.call_args[0][0]
        self.assertEqual(cmd_called, ["/usr/bin/fls", "-o", "2048", "-r", "-m", "/", str(self.dummy_image)])

    @patch("subprocess.run")
    def test_run_fls_without_offset(self, mock_subproc):
        """Verifies that fls command omits -o flag when offset is None or 0."""
        mock_subproc.return_value = MagicMock(returncode=0, stdout="test stdout", stderr="")

        stdout = self.parser._run_fls("/usr/bin/fls", self.dummy_image, offset=None)

        self.assertEqual(stdout, "test stdout")
        cmd_called = mock_subproc.call_args[0][0]
        self.assertEqual(cmd_called, ["/usr/bin/fls", "-r", "-m", "/", str(self.dummy_image)])

    @patch("pathlib.Path.exists", return_value=True)
    @patch.object(FilesystemParser, "_find_binary", return_value="/usr/bin/fls")
    @patch.object(FilesystemParser, "_discover_partition_offsets", return_value=["2048", "649216"])
    @patch.object(FilesystemParser, "_run_fls_on_partition")
    def test_parse_multi_partition_image_retains_provenance(
        self, mock_run_fls, mock_discover, mock_find_bin, mock_exists
    ):
        """Verifies multi-partition parse extracts artifacts from each partition with offset in metadata."""
        mock_run_fls.side_effect = [
            (SYNTHETIC_BODYFILE_DATA, "/usr/bin/fls -o 2048 -r -m / dummy.e01"),
            (SYNTHETIC_BODYFILE_DATA, "/usr/bin/fls -o 649216 -r -m / dummy.e01")
        ]

        artifacts = self.parser.parse("dummy_disk.e01", evidence_id="ev-disk-001")

        # 2 partitions * 2 lines each = 4 artifacts
        self.assertEqual(len(artifacts), 4)

        # Check provenance
        first_art = artifacts[0]
        self.assertEqual(first_art.evidence_id, "ev-disk-001")
        self.assertEqual(first_art.artifact_type, "file_record")
        self.assertEqual(first_art.normalized_fields.file_path, "/evil_script.ps1")
        self.assertEqual(first_art.raw_fields.get("partition_offset"), "2048")

        third_art = artifacts[2]
        self.assertEqual(third_art.evidence_id, "ev-disk-001")
        self.assertEqual(third_art.raw_fields.get("partition_offset"), "649216")


if __name__ == "__main__":
    unittest.main()
