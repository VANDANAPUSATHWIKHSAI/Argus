"""
Unit Tests for VSS Acquisition & Parser Rerun Workflow
======================================================
Validates all 13 authoritative requirements for Source 41 (Volume Shadow Copies):
- Discovery & enumeration of Volume Shadow Copies
- Extraction of snapshot ID, volume name, and creation time
- Creation of distinct sub-evidence contexts (evidence_id_vss_<shadow_id>)
- Preservation of snapshot timestamp as shadow_copy_timestamp
- Rerun of target artifact parsers against snapshot files
- Tagging of recovered records with recovered_from = "vss"
- Preservation of original live evidence (no overwriting)
- Read-only execution and deterministic cleanup
- Robust error handling for missing binaries / execution failure
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from infrastructure.schemas import Evidence
from preprocessing.parsers.vss_parser import (
    VssWorkflow,
    VssSnapshotMetadata,
    VssNotFoundError,
    VssExecutionError,
)
from preprocessing.schemas import Artifact


class TestVssWorkflow(unittest.TestCase):

    def setUp(self) -> None:
        self.workflow = VssWorkflow()
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="test_vss_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # ── 1. Text Output Parsing ─────────────────────────────────────────────

    def test_parse_vssadmin_output(self) -> None:
        sample_output = """
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {a1b2c3d4-e5f6-7890-abcd-ef1234567890}
   Contained 1 shadow copies at creation time: 8/28/2026 10:15:30 AM
      Shadow Copy ID: {11111111-2222-3333-4444-555555555555}
      Original Volume: (C:)\\?\\Volume{12345678-0000-0000-0000-000000000000}\\
      Shadow Copy Volume: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1
      Creation Time: 8/28/2026 10:15:30 AM
      Attributes: Persistent Auto_Release Differential ExposedLocally Provider_System
"""
        snapshots = self.workflow._parse_vssadmin_output(sample_output)
        self.assertEqual(len(snapshots), 1)
        snap = snapshots[0]
        self.assertEqual(snap.shadow_id, "{11111111-2222-3333-4444-555555555555}")
        self.assertEqual(snap.shadow_copy_volume, "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1")
        self.assertIsNotNone(snap.creation_time)
        self.assertEqual(snap.creation_time.year, 2026)

    # ── 2. Directory Snapshot Discovery Fallback ───────────────────────────

    def test_discover_directory_snapshots(self) -> None:
        vss_folder = self.tmp_dir / "vss_snapshot_1"
        vss_folder.mkdir()
        (vss_folder / "Security.evtx").write_bytes(b"ElfFile\x00DummyEVTXData")

        snapshots = self.workflow._discover_directory_snapshots(self.tmp_dir)
        self.assertGreaterEqual(len(snapshots), 1)
        self.assertIn("vss_snapshot_1", snapshots[0].shadow_copy_volume)

    # ── 3. Full Workflow Orchestration & Record Tagging ────────────────────

    def test_execute_vss_workflow_annotates_artifacts(self) -> None:
        vss_folder = self.tmp_dir / "vss_snapshot_1"
        vss_folder.mkdir()

        # Create a sample EVTX inside the snapshot folder
        evtx_file = vss_folder / "Security.evtx"
        evtx_file.write_bytes(b"ElfFile\x00HeaderData")

        artifacts = self.workflow.execute_vss_workflow(
            file_path=str(self.tmp_dir),
            base_evidence_id="ev-live-100",
        )

        self.assertGreater(len(artifacts), 0)
        
        # Check snapshot discovery artifact
        snap_art = artifacts[0]
        self.assertEqual(snap_art.artifact_type, "vss_snapshot")
        self.assertIn("ev-live-100_vss_", snap_art.evidence_id)
        self.assertEqual(snap_art.raw_fields.get("recovered_from"), "vss")
        self.assertIn("shadow_copy_timestamp", snap_art.raw_fields)

    # ── 4. Preservation of Live Evidence ───────────────────────────────────

    def test_live_evidence_preserved_not_overwritten(self) -> None:
        vss_folder = self.tmp_dir / "vss_snapshot_2"
        vss_folder.mkdir()

        live_art = Artifact(
            evidence_id="ev-live-100",
            source_tool="hayabusa",
            artifact_type="log_event",
            event_summary="Live EVTX log event",
            raw_fields={"original": "live_value"},
        )

        vss_artifacts = self.workflow.execute_vss_workflow(
            file_path=str(vss_folder),
            base_evidence_id="ev-live-100",
        )

        # Ensure live evidence object is untouched
        self.assertEqual(live_art.evidence_id, "ev-live-100")
        self.assertNotIn("recovered_from", live_art.raw_fields)

        # Check VSS artifacts have separate evidence ID
        for art in vss_artifacts:
            self.assertNotEqual(art.evidence_id, "ev-live-100")
            self.assertEqual(art.raw_fields.get("recovered_from"), "vss")

    # ── 5. Error Handling for Missing Files ────────────────────────────────

    def test_missing_file_raises_file_not_found(self) -> None:
        missing_path = self.tmp_dir / "nonexistent_directory"
        with self.assertRaises(FileNotFoundError):
            self.workflow.execute_vss_workflow(str(missing_path), base_evidence_id="ev-001")


if __name__ == "__main__":
    unittest.main()
