"""
PowerShellHistoryParser
=======================
Source 25: PowerShell Command History (ConsoleHost_history.txt)
Source Tool: "powershell_history"
Artifact Types Produced: "powershell_history"

Parses PowerShell PSReadLine command history files (e.g. ConsoleHost_history.txt).
Preserves verbatim raw command text, command sequence index, file metadata,
and user context extracted from path hierarchy.

CRITICAL: ConsoleHost_history.txt does NOT store per-command timestamps.
Timestamps remain None for commands to prevent false temporal correlation.
Commands are NEVER classified as malicious in Layer 2 preprocessing.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Optional, Any

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed Errors
# ---------------------------------------------------------------------------

class PowerShellHistoryNotFoundError(FileNotFoundError):
    """Raised when the specified PowerShell history file does not exist."""


class PowerShellHistoryParserError(RuntimeError):
    """Raised when parsing fails due to severe corruption or unreadable data."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class PowerShellHistoryParser:
    """Parses PowerShell PSReadLine command history text files."""

    def __init__(self) -> None:
        self._tool_version = get_tool_version("powershell_history")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse PowerShell history file at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise PowerShellHistoryNotFoundError(f"PowerShell history file not found: {file_path}")

        user = self._extract_user_from_path(str(src))
        content = self._read_file_content(src)

        lines = content.splitlines()
        artifacts: list[Artifact] = []

        ver = self._tool_version

        for seq, line in enumerate(lines, start=1):
            cmd_text = line.strip()
            if not cmd_text:
                continue

            summary = f"PowerShell command #{seq}: {cmd_text[:80]}"
            if len(cmd_text) > 80:
                summary += "..."

            raw_fields = {
                "command_text": cmd_text,
                "sequence_number": seq,
                "file_path": str(src),
                "file_name": src.name,
                "user": user,
                "tool_version": ver,
            }

            norm = NormalizedFields(
                user=user or None,
                process_command_line=cmd_text,
                process_name="powershell.exe",
                file_path=str(src),
                file_name=src.name,
            )

            art = Artifact(
                evidence_id=evidence_id,
                source_tool="powershell_history",
                artifact_type="powershell_history",
                timestamp=None,  # No per-command timestamps in ConsoleHost_history.txt
                timestamp_type="none",
                event_summary=summary,
                parser_version=ver,
                raw_fields=raw_fields,
                normalized_fields=norm,
            )
            artifacts.append(art)

        logger.info("PowerShellHistoryParser total: %d command artifacts from %s", len(artifacts), src.name)
        return artifacts

    @staticmethod
    def _read_file_content(path: Path) -> str:
        """Reads file attempting UTF-8, UTF-16, and Latin-1 encodings."""
        raw_bytes = path.read_bytes()
        if not raw_bytes:
            return ""

        # Try UTF-8 with BOM or standard UTF-8
        for enc in ("utf-8-sig", "utf-16", "utf-8", "latin-1"):
            try:
                return raw_bytes.decode(enc)
            except (UnicodeDecodeError, ValueError):
                continue
        return raw_bytes.decode("latin-1", errors="replace")

    @staticmethod
    def _extract_user_from_path(path_str: str) -> Optional[str]:
        """Extracts username from standard Windows user directory paths if present."""
        m = re.search(r"[\\/]Users[\\/]([^\\/]+)[\\/]", path_str, re.IGNORECASE)
        if m:
            user = m.group(1)
            if user.lower() not in ("public", "default", "default user", "all users"):
                return user
        return None
