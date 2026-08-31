# Windows Event Log parser using Hayabusa
# Source tool: "hayabusa"
# Artifact types produced: "log_event", "evasion_indicator"
# Raw output format: JSON / JSONL (one record per event log entry)
# Hayabusa docs: https://github.com/Yamato-Security/hayabusa
# Evasion indicator checks:
#   - Event ID 1102: audit log cleared (Microsoft-Windows-Eventlog / Security channel)
#   - EventRecordID sequence gaps: deleted records between two IDs

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed errors — never silently swallow failures
# ---------------------------------------------------------------------------

class HayabusaNotFoundError(FileNotFoundError):
    """Raised when the `hayabusa` binary cannot be found on PATH."""


class HayabusaExecutionError(RuntimeError):
    """Raised when Hayabusa exits with a non-zero return code."""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class EvtxParser:
    """Parses Windows Event Log (.evtx) files via Hayabusa into Artifact records.

    Hayabusa runs Sigma-based detection rules against each .evtx file and outputs
    one JSON record per event log entry, including:
      - Timestamp            — ISO-8601 event time
      - Computer             — hostname that generated the event
      - EventID              — Windows event identifier
      - RuleTitle            — matched Sigma rule name (empty string if no match)
      - Level                — severity level (informational / low / medium / high / critical)
      - Channel              — log channel (Security, System, Application, …)
      - Details              — human-readable interpretation of event fields
      - MitreTactics         — list of MITRE ATT&CK tactic names (may be absent)
      - MitreTags            — list of MITRE technique IDs (may be absent)

    Shell command executed:
        hayabusa json-timeline -f <evtx_path> -o <tmp>.jsonl -L -q

    Flags:
      -f   input file
      -o   output JSONL path
      -L   output as JSONL (one JSON object per line)
      -q   quiet — suppress progress bars and banners
    """

    # Hayabusa emits timestamps in two main shapes:
    #   "2021-09-03 03:23:56.840 +00:00"  — space-separated, 3-digit ms, colon in offset
    #   "2021-09-03T03:23:56.840000+00:00" — ISO-8601
    # Python's strptime %z only accepts ±HHMM (no colon), so we normalise first.
    _TS_RE = re.compile(
        r'^(?P<dt>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
        r'(?:\.(?P<frac>\d+))?'
        r'\s*(?P<tz>[+-]\d{2}:?\d{2}|Z)?$'
    )

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse the .evtx file at *file_path* and return a list of Artifact records.

        Args:
            file_path:   Absolute path to the .evtx file to analyse.
            evidence_id: FK linking back to the ``infrastructure.Evidence`` record.
                         Pass an empty string during unit tests / standalone use.

        Returns:
            List of :class:`~preprocessing.schemas.Artifact` objects, one per
            Hayabusa JSON line in the output.

        Raises:
            HayabusaNotFoundError:  Binary not on PATH.
            HayabusaExecutionError: Binary exited with non-zero code.
            FileNotFoundError:      *file_path* does not exist.
        """
        self._tool_version = get_tool_version("hayabusa")
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"EVTX file not found: {file_path}")

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            self._run_hayabusa(src, tmp_path)
            artifacts = self._parse_jsonl(tmp_path, evidence_id)
        finally:
            tmp_path.unlink(missing_ok=True)

        # Post-parse evasion indicator checks (non-raising; append indicators)
        artifacts.extend(self._check_evasion_indicators(artifacts, evidence_id))
        return artifacts

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _run_hayabusa(self, evtx_path: Path, output_path: Path) -> None:
        """Shell out to `hayabusa json-timeline` and write JSONL to *output_path*."""
        cmd = [
            "hayabusa",
            "json-timeline",
            "-f", str(evtx_path),
            "-o", str(output_path),
            "-L",   # JSONL (one object per line)
            "-q",   # quiet — no progress bars or banners
        ]
        logger.debug("Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,   # 5-minute ceiling for large .evtx files
            )
        except FileNotFoundError:
            raise HayabusaNotFoundError(
                "hayabusa binary not found on PATH. "
                "Install Hayabusa from https://github.com/Yamato-Security/hayabusa "
                "and ensure it is accessible as `hayabusa`."
            )

        if result.returncode != 0:
            raise HayabusaExecutionError(
                f"Hayabusa exited with code {result.returncode}.\n"
                f"stdout: {result.stdout.strip()}\n"
                f"stderr: {result.stderr.strip()}"
            )

        logger.info(
            "Hayabusa finished: evtx=%s output=%s",
            evtx_path.name,
            output_path,
        )

    def _parse_jsonl(self, jsonl_path: Path, evidence_id: str) -> list[Artifact]:
        """Read Hayabusa JSONL output and convert each line to an Artifact."""
        artifacts: list[Artifact] = []

        with jsonl_path.open(encoding="utf-8", errors="replace") as fh:
            for lineno, raw_line in enumerate(fh, start=1):
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    record: dict = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "Skipping malformed JSON on line %d: %s", lineno, exc
                    )
                    continue

                artifacts.append(self._record_to_artifact(record, evidence_id))

        logger.info("Parsed %d Hayabusa records from %s", len(artifacts), jsonl_path)
        return artifacts

    # -----------------------------------------------------------------------
    # Evasion indicator checks
    # -----------------------------------------------------------------------

    def _check_evasion_indicators(
        self,
        artifacts: list[Artifact],
        evidence_id: str,
    ) -> list[Artifact]:
        """Scan the parsed artifact list for common anti-forensic evasion indicators.

        This is a best-effort, heuristic check — it flags what is detectable
        from Hayabusa's output and should be named an *indicator*, not a
        guarantee of tampering.

        Checks performed:
          1. **Event ID 1102** — The Windows Security audit log was cleared.
             This is a well-known anti-forensic action.  Each occurrence emits
             one ``evasion_indicator`` artifact.

          2. **EventRecordID sequence gap** — Hayabusa reports a per-channel
             monotonic record counter.  A gap between consecutive observed IDs
             (e.g. IDs 500 → 750 with no intervening records) suggests that
             records in that range were deleted or the log was partially cleared.
             One artifact is emitted per detected gap, describing the missing
             range.

        Returns a (possibly empty) list of new evasion_indicator Artifacts.
        Errors inside this method are logged as warnings and never raise, so a
        bad record cannot abort the whole parse.
        """
        indicators: list[Artifact] = []

        # ── Check 1: Event ID 1102 (audit log cleared) ──────────────────────
        for art in artifacts:
            try:
                eid = art.raw_fields.get("EventID")
                if eid is not None and int(eid) == 1102:
                    channel  = art.raw_fields.get("Channel", "Security")
                    computer = art.raw_fields.get("Computer") or "(unknown)"
                    details  = art.raw_fields.get("Details", "")
                    logger.warning(
                        "Evasion indicator: Event ID 1102 (audit log cleared) "
                        "on host %s at %s",
                        computer, art.timestamp,
                    )
                    indicators.append(Artifact(
                        evidence_id=evidence_id,
                        source_tool="hayabusa",
                        artifact_type="evasion_indicator",
                        timestamp=art.timestamp,
                        raw_fields={
                            "indicator":    "audit_log_cleared",
                            "event_id":     1102,
                            "channel":      channel,
                            "computer":     computer,
                            "details":      details,
                            "tool_version": getattr(self, "_tool_version", get_tool_version("hayabusa")),
                            "note": (
                                "Event ID 1102 indicates the Windows Security audit log "
                                "was intentionally cleared.  This is a well-known "
                                "anti-forensic technique (T1070.001).  "
                                "This is an indicator, not a guarantee of malicious intent."
                            ),
                        },
                        normalized_fields=NormalizedFields(
                            host=computer or None,
                            rule_name="audit_log_cleared",
                            severity="high",
                        ),
                    ))
            except (TypeError, ValueError) as exc:
                logger.warning("Error checking Event ID 1102 on artifact: %s", exc)

        # ── Check 2: EventRecordID sequence gaps ─────────────────────────────
        # Group records by Channel, collect their EventRecordIDs, sort, and
        # look for gaps larger than 1 between consecutive observed IDs.
        # A gap means records in that range are absent from the .evtx file.
        from collections import defaultdict
        channel_ids: dict[str, list[int]] = defaultdict(list)

        for art in artifacts:
            try:
                raw_id = art.raw_fields.get("EventRecordID")
                if raw_id is None:
                    continue
                rec_id  = int(raw_id)
                channel = art.raw_fields.get("Channel") or "unknown"
                channel_ids[channel].append(rec_id)
            except (TypeError, ValueError):
                continue

        for channel, ids in channel_ids.items():
            if len(ids) < 2:
                continue
            sorted_ids = sorted(ids)
            for i in range(len(sorted_ids) - 1):
                lo, hi = sorted_ids[i], sorted_ids[i + 1]
                gap = hi - lo
                if gap > 1:
                    missing_count = gap - 1
                    logger.warning(
                        "Evasion indicator: EventRecordID gap in channel %r: "
                        "IDs %d–%d missing (%d records absent)",
                        channel, lo + 1, hi - 1, missing_count,
                    )
                    indicators.append(Artifact(
                        evidence_id=evidence_id,
                        source_tool="hayabusa",
                        artifact_type="evasion_indicator",
                        timestamp=None,   # gap has no single timestamp
                        raw_fields={
                            "indicator":       "event_record_id_gap",
                            "channel":         channel,
                            "gap_start_id":    lo + 1,
                            "gap_end_id":      hi - 1,
                            "missing_records":  missing_count,
                            "last_seen_id":    lo,
                            "next_seen_id":    hi,
                            "tool_version":    getattr(self, "_tool_version", get_tool_version("hayabusa")),
                            "note": (
                                f"EventRecordID gap detected in channel {channel!r}: "
                                f"record IDs {lo+1}–{hi-1} ({missing_count} records) "
                                "are absent from the .evtx file.  "
                                "This may indicate selective log deletion or partial log "
                                "clearing (T1070.001).  "
                                "This is an indicator, not a guarantee of tampering — "
                                "gaps can also result from log rotation or service restarts."
                            ),
                        },
                        normalized_fields=NormalizedFields(
                            rule_name="event_record_id_gap",
                            severity="medium",
                        ),
                    ))

        if indicators:
            logger.info(
                "EvtxParser: %d evasion indicator(s) emitted for evidence_id=%s",
                len(indicators), evidence_id,
            )
        return indicators

    # -----------------------------------------------------------------------
    # Field mapping
    # -----------------------------------------------------------------------

    def _record_to_artifact(self, record: dict, evidence_id: str) -> Artifact:
        """Map one parsed Hayabusa JSON record to an :class:`Artifact`."""
        eid = record.get("EventID")
        channel = record.get("Channel") or "Security"
        computer = record.get("Computer") or ""
        summary = f"Event ID {eid} in {channel} on {computer}" if eid else f"Log event in {channel}"
        ver = getattr(self, "_tool_version", get_tool_version("hayabusa"))
        return Artifact(
            evidence_id=evidence_id,
            source_tool="hayabusa",
            artifact_type="log_event",
            timestamp=self._parse_timestamp(record.get("Timestamp")),
            timestamp_type="event",
            event_summary=summary,
            parser_version=ver,
            raw_fields={**record, "tool_version": ver},
            normalized_fields=self._normalize(record),
        )

    @staticmethod
    def _normalize(record: dict) -> NormalizedFields:
        """Extract the small correlation-friendly field set from a Hayabusa record."""
        # MitreTactics and MitreTags are lists in the JSON; store as comma-joined
        # strings so NormalizedFields.rule_name stays a plain str field.
        mitre_tactics: list = record.get("MitreTactics") or []
        mitre_tags:    list = record.get("MitreTags")    or []

        rule_parts = [r for r in [
            record.get("RuleTitle", "").strip(),
            ", ".join(mitre_tactics) if mitre_tactics else "",
            ", ".join(str(t) for t in mitre_tags) if mitre_tags else "",
        ] if r]
        rule_name: Optional[str] = " | ".join(rule_parts) if rule_parts else None

        return NormalizedFields(
            host=record.get("Computer") or None,
            rule_name=rule_name,
            severity=record.get("Level") or None,
        )

    def _parse_timestamp(self, raw: Optional[str]) -> Optional[datetime]:
        """Parse Hayabusa's timestamp string to a timezone-aware datetime.

        Handles the two shapes Hayabusa emits:
          - ``"2024-03-15 08:22:11.000 +00:00"``  (space-separated, 3-digit ms)
          - ``"2024-03-15T08:22:11.840000+00:00"`` (ISO-8601)
        Returns ``None`` for empty or unrecognised strings.
        """
        if not raw:
            return None
        m = self._TS_RE.match(raw.strip())
        if not m:
            logger.warning("Unrecognised Hayabusa timestamp format: %r", raw)
            return None

        dt_str  = m.group("dt").replace(" ", "T")          # normalise space → T
        frac    = m.group("frac") or ""
        tz_str  = (m.group("tz") or "").replace(":", "")   # remove colon: +00:00 → +0000

        # Pad / truncate fractional seconds to exactly 6 digits for %f
        if frac:
            frac = (frac + "000000")[:6]
            iso = f"{dt_str}.{frac}{tz_str}"
            fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
        else:
            iso = f"{dt_str}{tz_str}"
            fmt = "%Y-%m-%dT%H:%M:%S%z"

        try:
            return datetime.strptime(iso, fmt)
        except ValueError:
            logger.warning("Failed to parse normalised timestamp %r (from %r)", iso, raw)
            return None
