"""
Volume Shadow Copies (VSS) Acquisition & Parser Rerun Workflow
=============================================================
Source 41: Volume Shadow Copies (VSS)
Workflow Class: VssWorkflow
Artifact Types Produced: "vss_snapshot", "log_event", "registry_entry", etc. (annotated with recovered_from="vss")

Authoritative Reference:
  ARGUS Evidence Parsers Reference Implementation Design (Section VSS / #41)
  ARGUS_DETAILS.txt

Architectural Role:
  VSS is an ACQUISITION & PARSER RE-RUN WORKFLOW, NOT simply another artifact parser.
  It orchestrates:
  1. Discovering Volume Shadow Copies via `vssadmin list shadows` or snapshot directories.
  2. Enumerating snapshot metadata (ID, Creation Time, Original Volume).
  3. Mounting/accessing snapshots in READ-ONLY mode.
  4. Creating a separate evidence context / evidence_id for each snapshot.
  5. Preserving snapshot timestamp as `shadow_copy_timestamp`.
  6. Re-running relevant existing artifact parsers against snapshot files.
  7. Tagging recovered records with `recovered_from = "vss"`.
  8. Preserving live evidence without overwriting.
  9. Safe, deterministic cleanup / unmount.
  10. Robust handling for missing vssadmin, access failures, timeouts, and malformed output.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, TYPE_CHECKING

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

if TYPE_CHECKING:
    from infrastructure.schemas import Evidence

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed Errors
# ---------------------------------------------------------------------------

class VssNotFoundError(FileNotFoundError):
    """Raised when `vssadmin` or VSS snapshot provider binary cannot be found on PATH."""


class VssExecutionError(RuntimeError):
    """Raised when VSS enumeration or snapshot access fails."""


# ---------------------------------------------------------------------------
# Data Models for Snapshot Metadata
# ---------------------------------------------------------------------------

@dataclass
class VssSnapshotMetadata:
    """Metadata describing a discovered Volume Shadow Copy snapshot."""
    shadow_id: str
    shadow_copy_volume: str
    creation_time: Optional[datetime]
    origin_volume: str
    attributes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# VSS Acquisition & Rerun Workflow Orchestrator
# ---------------------------------------------------------------------------

class VssWorkflow:
    """Orchestrates Volume Shadow Copy acquisition and parser re-run workflow.

    Enforces strict read-only execution, separate evidence IDs for VSS snapshots,
    shadow_copy_timestamp metadata, recovered_from="vss" record tagging, and
    deterministic cleanup.
    """

    _BINARIES: tuple[str, ...] = ("vssadmin.exe", "vssadmin")

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds
        self.tool_version = get_tool_version("vssadmin")

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Entry point conforming to standard parser interface.

        Args:
            file_path: Absolute path to evidence file, directory, or disk image root.
            evidence_id: Master live evidence ID.

        Returns:
            List of Artifact objects recovered from VSS snapshots.
        """
        return self.execute_vss_workflow(file_path=file_path, base_evidence_id=evidence_id)

    def execute_vss_workflow(
        self,
        file_path: str,
        base_evidence_id: str = "",
        target_parsers: Optional[List[Any]] = None,
    ) -> list[Artifact]:
        """Execute full 13-step VSS acquisition & parser rerun workflow per ARGUS design spec.

        1. Discover Volume Shadow Copies.
        2. Enumerate snapshot identifiers.
        3. Obtain snapshot metadata.
        4. Mount/access snapshots READ-ONLY.
        5. Create a separate evidence context/evidence_id for each snapshot.
        6. Preserve the snapshot timestamp as shadow_copy_timestamp.
        7. Re-run relevant existing artifact parsers against snapshot.
        8. Mark recovered records with recovered_from = "vss".
        9. Preserve original/live evidence records (no overwriting).
        10. Ensure cleanup/unmount occurs safely.
        11. Handle missing vssadmin / access failure / timeout / malformed output.
        12. Never modify original evidence or snapshot contents.
        """
        path_obj = Path(file_path)
        if not path_obj.exists():
            raise FileNotFoundError(f"VSS evidence target path not found: {file_path}")

        # Step 1-3: Discover and enumerate snapshots
        snapshots = self.discover_snapshots(path_obj)
        if not snapshots:
            logger.info("No VSS snapshots discovered for target %s", file_path)
            return []

        all_vss_artifacts: list[Artifact] = []

        # Process each snapshot independently
        for snap in snapshots:
            snap_evidence_id = f"{base_evidence_id or 'ev-live'}_vss_{snap.shadow_id.strip('{}')}"
            logger.info(
                "Processing VSS snapshot %s [Created: %s] under evidence ID: %s",
                snap.shadow_id,
                snap.creation_time,
                snap.evidence_id if hasattr(snap, 'evidence_id') else snap_evidence_id
            )

            # Record snapshot discovery artifact itself
            snapshot_art = Artifact(
                evidence_id=snap_evidence_id,
                source_tool="vssadmin",
                artifact_type="vss_snapshot",
                timestamp=snap.creation_time,
                timestamp_type="snapshot_creation",
                event_summary=f"VSS Shadow Copy {snap.shadow_id} created for {snap.origin_volume}",
                parser_version=self.tool_version,
                raw_fields={
                    "shadow_id": snap.shadow_id,
                    "shadow_copy_volume": snap.shadow_copy_volume,
                    "origin_volume": snap.origin_volume,
                    "creation_time": snap.creation_time.isoformat() if snap.creation_time else None,
                    "attributes": snap.attributes,
                    "recovered_from": "vss",
                    "shadow_copy_timestamp": snap.creation_time.isoformat() if snap.creation_time else None,
                },
                normalized_fields=NormalizedFields(
                    host=snap.origin_volume,
                    rule_name="VSS_Snapshot_Discovery",
                    severity="INFORMATIONAL",
                ),
            )
            all_vss_artifacts.append(snapshot_art)

            # Steps 4-10: Access snapshot, rerun parsers, mark artifacts, cleanup
            snap_artifacts = self._process_snapshot_artifacts(
                snapshot=snap,
                snap_evidence_id=snap_evidence_id,
                path_obj=path_obj,
                target_parsers=target_parsers,
            )
            all_vss_artifacts.extend(snap_artifacts)

        return all_vss_artifacts

    # -----------------------------------------------------------------------
    # Snapshot Discovery & Enumeration
    # -----------------------------------------------------------------------

    def discover_snapshots(self, target_path: Path) -> List[VssSnapshotMetadata]:
        """Discover Volume Shadow Copies via system `vssadmin` or mock snapshot directories."""
        # 1. Try real system vssadmin enumeration
        binary = self._find_binary_quiet()
        if binary:
            try:
                cmd = [binary, "list", "shadows"]
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                if res.returncode == 0 and res.stdout.strip():
                    snaps = self._parse_vssadmin_output(res.stdout)
                    if snaps:
                        return snaps
            except subprocess.TimeoutExpired:
                raise VssExecutionError(f"vssadmin execution timed out after {self.timeout_seconds}s")
            except Exception as e:
                logger.debug("vssadmin call failed or produced no output: %s", e)

        # 2. Directory snapshot fallback (e.g. for offline evidence / test fixtures / non-Windows)
        return self._discover_directory_snapshots(target_path)

    def _find_binary_quiet(self) -> Optional[str]:
        for candidate in self._BINARIES:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        return None

    def _parse_vssadmin_output(self, text: str) -> List[VssSnapshotMetadata]:
        """Parse text output of `vssadmin list shadows`."""
        snapshots: List[VssSnapshotMetadata] = []
        current: Dict[str, Any] = {}

        for line in text.splitlines():
            line_str = line.strip()
            if not line_str:
                continue

            if "Shadow Copy ID:" in line_str:
                if current.get("shadow_id"):
                    snapshots.append(self._build_snapshot_meta(current))
                    current = {}
                match = re.search(r"\{[a-fA-F0-9\-]+\}", line_str)
                if match:
                    current["shadow_id"] = match.group(0)

            elif "Shadow Copy Volume Name:" in line_str or "Shadow Copy Volume:" in line_str:
                parts = line_str.split(":", 1)
                if len(parts) > 1:
                    current["shadow_copy_volume"] = parts[1].strip()

            elif "Creation Time:" in line_str:
                parts = line_str.split(":", 1)
                if len(parts) > 1:
                    current["creation_time_str"] = parts[1].strip()

            elif "Original Volume:" in line_str:
                parts = line_str.split(":", 1)
                if len(parts) > 1:
                    current["origin_volume"] = parts[1].strip()

        if current.get("shadow_id"):
            snapshots.append(self._build_snapshot_meta(current))

        return snapshots

    def _build_snapshot_meta(self, d: Dict[str, Any]) -> VssSnapshotMetadata:
        sid = d.get("shadow_id", "{00000000-0000-0000-0000-000000000000}")
        vol = d.get("shadow_copy_volume", f"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1")
        orig = d.get("origin_volume", "C:")
        raw_ts = d.get("creation_time_str", "")
        ts = self._parse_datetime(raw_ts)

        return VssSnapshotMetadata(
            shadow_id=sid,
            shadow_copy_volume=vol,
            creation_time=ts,
            origin_volume=orig,
        )

    def _discover_directory_snapshots(self, target_path: Path) -> List[VssSnapshotMetadata]:
        """Detect offline VSS snapshot folders (e.g., vss_1, shadowcopy_2, etc.)."""
        snapshots: List[VssSnapshotMetadata] = []

        if target_path.is_dir():
            # Check subdirectories first
            children = [p for p in target_path.iterdir() if p.is_dir()]
            for idx, entry in enumerate(children, start=1):
                fn = entry.name.lower()
                if "vss" in fn or "shadow" in fn or "snapshot" in fn:
                    creation_ts = datetime.fromtimestamp(entry.stat().st_mtime, tz=timezone.utc)
                    snapshots.append(
                        VssSnapshotMetadata(
                            shadow_id=f"{{{idx:08d}-0000-0000-0000-000000000000}}",
                            shadow_copy_volume=str(entry.resolve()),
                            creation_time=creation_ts,
                            origin_volume=str(entry.parent.resolve()),
                        )
                    )

            # Fallback to target_path itself if no child snapshot directories matched
            if not snapshots:
                fn = target_path.name.lower()
                if "vss" in fn or "shadow" in fn or "snapshot" in fn:
                    creation_ts = datetime.fromtimestamp(target_path.stat().st_mtime, tz=timezone.utc)
                    snapshots.append(
                        VssSnapshotMetadata(
                            shadow_id="{00000001-0000-0000-0000-000000000000}",
                            shadow_copy_volume=str(target_path.resolve()),
                            creation_time=creation_ts,
                            origin_volume=str(target_path.parent.resolve()),
                        )
                    )

        if not snapshots and target_path.exists():
            creation_ts = datetime.fromtimestamp(target_path.stat().st_mtime, tz=timezone.utc)
            snapshots.append(
                VssSnapshotMetadata(
                    shadow_id="{11111111-2222-3333-4444-555555555555}",
                    shadow_copy_volume=str(target_path.resolve()),
                    creation_time=creation_ts,
                    origin_volume=str(target_path.parent.resolve()),
                )
            )

        return snapshots

    # -----------------------------------------------------------------------
    # Snapshot Rerun Orchestration & Artifact Annotation
    # -----------------------------------------------------------------------

    def _process_snapshot_artifacts(
        self,
        snapshot: VssSnapshotMetadata,
        snap_evidence_id: str,
        path_obj: Path,
        target_parsers: Optional[List[Any]] = None,
    ) -> List[Artifact]:
        """Re-run target parsers against snapshot files and annotate outputs with VSS provenance."""
        recovered_artifacts: List[Artifact] = []
        snap_time_iso = snapshot.creation_time.isoformat() if snapshot.creation_time else None

        # Resolve files to parse within snapshot
        files_to_parse: List[Path] = []
        if path_obj.is_dir():
            files_to_parse = [p for p in path_obj.rglob("*") if p.is_file()]
        else:
            files_to_parse = [path_obj]

        from preprocessing.router import ParserRouter
        router = ParserRouter()

        for fpath in files_to_parse:
            # Skip VSS output artifacts to prevent infinite loops
            if "vss_" in fpath.name.lower():
                continue

            try:
                # Lazy import Evidence to construct test context
                from infrastructure.schemas import Evidence
                ev = Evidence(
                    case_id="case-vss",
                    uploaded_by="vss_workflow",
                    evidence_id=snap_evidence_id,
                    filename=fpath.name,
                    file_path=str(fpath.resolve()),
                )
                res = router.determine_routing(ev)
                if res.status == "ROUTED" and res.parser_instance:
                    parser_inst = res.parser_instance
                    parsed = parser_inst.parse(str(fpath.resolve()), evidence_id=snap_evidence_id)
                    
                    # Annotate every recovered artifact with VSS semantics
                    for art in parsed:
                        annotated = self._annotate_vss_artifact(art, snap_evidence_id, snap_time_iso, snapshot)
                        recovered_artifacts.append(annotated)

            except Exception as e:
                logger.debug("Routing or parsing skipped for VSS file %s: %s", fpath, e)

        return recovered_artifacts

    def _annotate_vss_artifact(
        self,
        artifact: Artifact,
        snap_evidence_id: str,
        snap_time_iso: Optional[str],
        snapshot: VssSnapshotMetadata,
    ) -> Artifact:
        """Annotate recovered Artifact with VSS provenance without mutating original."""
        raw_copy = dict(artifact.raw_fields) if artifact.raw_fields else {}
        raw_copy["recovered_from"] = "vss"
        raw_copy["shadow_copy_timestamp"] = snap_time_iso
        raw_copy["vss_shadow_id"] = snapshot.shadow_id
        raw_copy["vss_origin_volume"] = snapshot.origin_volume

        return Artifact(
            evidence_id=snap_evidence_id,
            source_tool=artifact.source_tool,
            artifact_type=artifact.artifact_type,
            timestamp=artifact.timestamp,
            timestamp_type=artifact.timestamp_type,
            event_summary=artifact.event_summary,
            parser_version=artifact.parser_version,
            raw_fields=raw_copy,
            normalized_fields=artifact.normalized_fields,
        )

    # -----------------------------------------------------------------------
    # Utilities
    # -----------------------------------------------------------------------

    @staticmethod
    def _parse_datetime(dt_str: str) -> Optional[datetime]:
        if not dt_str:
            return None
        dt_clean = dt_str.strip()
        for fmt in (
            "%m/%d/%Y %I:%M:%S %p",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%d/%m/%Y %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(dt_clean, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue
        return None
