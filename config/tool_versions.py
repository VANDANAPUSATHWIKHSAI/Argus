"""
config/tool_versions
====================
Thin reader for ``config/tool_versions.json``, which is written by
``setup_tools.sh`` after verifying each external forensic binary.

Every parser calls :func:`get_tool_version` to stamp ``raw_fields["tool_version"]``
on every Artifact it produces.  This makes every finding traceable to the exact
tool version that produced it — essential for triage if a tool bug is discovered
after the fact.

File format (written by setup_tools.sh)::

    {
        "written_at": "2024-03-15T08:22:11Z",
        "hayabusa":   "2.18.0",
        "zeek":       "6.0.3",
        "suricata":   "7.0.3",
        "volatility3": "2.7.1",
        "regripper":  "20201114"
    }

If the file is absent (e.g. a developer workstation where setup_tools.sh has
never been run), :func:`get_tool_version` returns ``"unknown"`` so parsers
continue to function without error.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Canonical path — resolved relative to this file so it works regardless of cwd.
_VERSIONS_FILE: Path = Path(__file__).parent / "tool_versions.json"

# Module-level cache — loaded once on first access, never reloaded at runtime.
_cache: Optional[dict] = None


def _load() -> dict:
    """Load and return the tool_versions.json dict, or {} if absent/corrupt."""
    global _cache
    if _cache is not None:
        return _cache

    if not _VERSIONS_FILE.exists():
        logger.debug(
            "tool_versions.json not found at %s — tool versions will be 'unknown'. "
            "Run setup_tools.sh to generate this file.",
            _VERSIONS_FILE,
        )
        _cache = {}
        return _cache

    try:
        with _VERSIONS_FILE.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"Expected a JSON object, got {type(data).__name__}")
        _cache = data
        logger.debug("Loaded tool versions from %s: %s", _VERSIONS_FILE, _cache)
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        logger.warning(
            "Failed to read tool_versions.json (%s) — tool versions will be 'unknown'.",
            exc,
        )
        _cache = {}

    return _cache


def get_tool_version(tool_name: str) -> str:
    """Return the version string for *tool_name*, or ``"unknown"`` if not recorded.

    Args:
        tool_name: Key as written by setup_tools.sh, e.g. ``"hayabusa"``,
                   ``"zeek"``, ``"suricata"``, ``"volatility3"``, ``"regripper"``.

    Returns:
        Version string (e.g. ``"2.18.0"``) or ``"unknown"``.
    """
    return str(_load().get(tool_name, "unknown"))


def get_all_versions() -> dict:
    """Return the full versions dict (a copy).  Excludes the ``written_at`` key."""
    data = _load()
    return {k: v for k, v in data.items() if k != "written_at"}


def reload() -> None:
    """Force a reload of tool_versions.json on the next :func:`get_tool_version` call.

    Only needed in tests that write the file and immediately read it back.
    """
    global _cache
    _cache = None
