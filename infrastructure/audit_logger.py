"""
ARGUS — Cryptographically Hash-Chained Audit Logger
=====================================================
Every audit log entry carries:
  - prev_hash   : entry_hash of the immediately preceding entry for this tenant,
                  or the sentinel string "GENESIS" for the first entry.
  - entry_hash  : SHA-256( prev_hash + canonical_entry )
                  where canonical_entry is a deterministic JSON representation
                  of all fields EXCEPT entry_hash itself, serialised with
                  sort_keys=True, separators=(',', ':'), UTF-8 encoded.

This makes any post-hoc modification, deletion, insertion, or reordering
of entries detectable via verify_chain().

Design constraints:
  - Independent chain per tenant (keyed by tenant_id).
  - Thread-safe: a per-tenant re-entrant lock guards both the in-memory chain
    state and the file append so that concurrent writes never corrupt the chain.
  - Backward-compatible: existing callers that pass a plain dict to logger.info()
    receive the same API — the chaining is applied transparently inside the
    JSONFormatter before the line is written.
  - No secrets or raw evidence bytes are stored in the audit record.
"""

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── Per-tenant chain state ────────────────────────────────────────────────────

class _TenantChainState:
    """Holds the running chain head for one tenant and a lock for that tenant."""

    __slots__ = ("last_hash", "lock")

    def __init__(self) -> None:
        self.last_hash: str = "GENESIS"
        self.lock: threading.RLock = threading.RLock()


# Global registry: tenant_id -> _TenantChainState
# Protected by _REGISTRY_LOCK when new tenants are added.
_CHAIN_REGISTRY: dict[str, _TenantChainState] = {}
_REGISTRY_LOCK = threading.Lock()


def _get_chain_state(tenant_id: str) -> _TenantChainState:
    """Returns (and lazily creates) the chain state for *tenant_id*."""
    with _REGISTRY_LOCK:
        if tenant_id not in _CHAIN_REGISTRY:
            state = _TenantChainState()
            # Try to read the last entry from an existing log file so that we
            # correctly continue a chain that was written in a previous process.
            state.last_hash = _read_last_entry_hash(tenant_id)
            _CHAIN_REGISTRY[tenant_id] = state
        return _CHAIN_REGISTRY[tenant_id]


def _read_last_entry_hash(tenant_id: str) -> str:
    """
    Reads the last JSONL line in the audit log for *tenant_id* and returns its
    entry_hash.  Falls back to "GENESIS" if the file does not exist or the last
    line has no entry_hash.
    """
    base_logs_dir = os.getenv("ARGUS_LOGS_DIR", "logs")
    log_file = Path(base_logs_dir) / "audit" / f"{tenant_id}.jsonl"
    if not log_file.exists():
        return "GENESIS"
    try:
        last_line = ""
        with log_file.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
        if last_line:
            entry = json.loads(last_line)
            return entry.get("entry_hash", "GENESIS")
    except Exception:
        pass
    return "GENESIS"


# ── Hash computation ──────────────────────────────────────────────────────────

def _canonicalize(entry: dict) -> bytes:
    """
    Produce a deterministic UTF-8 byte sequence for *entry*, excluding the
    'entry_hash' key (which is not yet known when the hash is computed).
    """
    filtered = {k: v for k, v in entry.items() if k != "entry_hash"}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _compute_entry_hash(prev_hash: str, entry: dict) -> str:
    """
    Returns hex-encoded SHA-256 over (prev_hash + canonical_entry).
    The concatenation is done at the byte level:
        SHA256( prev_hash_utf8_bytes + canonical_entry_bytes )
    """
    canonical = _canonicalize(entry)
    payload = prev_hash.encode("utf-8") + canonical
    return hashlib.sha256(payload).hexdigest()


# ── Chain verification ────────────────────────────────────────────────────────

class AuditChainVerificationError(Exception):
    """Raised when verify_chain() detects tampering or corruption."""


def verify_chain(tenant_id: str) -> dict:
    """
    Re-reads every line of the audit log for *tenant_id* and verifies:

    - The first entry carries prev_hash == "GENESIS".
    - Every subsequent entry's prev_hash equals the entry_hash of the
      preceding entry (detects deletions, insertions, reorderings).
    - Every entry's entry_hash == SHA256(prev_hash + canonical_entry)
      (detects in-place modifications).

    Returns a dict on success:
        {"ok": True, "entries_verified": N, "tenant_id": tenant_id}

    Raises AuditChainVerificationError on any integrity failure with a
    human-readable description of the first detected problem.
    """
    base_logs_dir = os.getenv("ARGUS_LOGS_DIR", "logs")
    log_file = Path(base_logs_dir) / "audit" / f"{tenant_id}.jsonl"

    if not log_file.exists():
        # An empty / non-existent log is vacuously valid.
        return {"ok": True, "entries_verified": 0, "tenant_id": tenant_id}

    entries = []
    try:
        with log_file.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise AuditChainVerificationError(
                        f"Line {lineno}: JSON decode error — {exc}"
                    ) from exc
                entries.append((lineno, entry))
    except AuditChainVerificationError:
        raise
    except Exception as exc:
        raise AuditChainVerificationError(f"Could not read audit log: {exc}") from exc

    expected_prev = "GENESIS"
    for idx, (lineno, entry) in enumerate(entries):
        # ── Check 1: prev_hash linkage ────────────────────────────────────
        actual_prev = entry.get("prev_hash")
        if actual_prev != expected_prev:
            raise AuditChainVerificationError(
                f"Line {lineno} (entry #{idx + 1}): prev_hash mismatch. "
                f"Expected '{expected_prev[:16]}…', got '{str(actual_prev)[:16]}…'. "
                f"Possible cause: entry deleted, inserted, or reordered."
            )

        # ── Check 2: entry_hash correctness ───────────────────────────────
        stored_hash = entry.get("entry_hash")
        if not stored_hash:
            raise AuditChainVerificationError(
                f"Line {lineno} (entry #{idx + 1}): missing entry_hash field."
            )
        recomputed = _compute_entry_hash(expected_prev, entry)
        if recomputed != stored_hash:
            raise AuditChainVerificationError(
                f"Line {lineno} (entry #{idx + 1}): entry_hash mismatch — "
                f"stored='{stored_hash[:16]}…', recomputed='{recomputed[:16]}…'. "
                f"Entry contents may have been modified."
            )

        expected_prev = stored_hash

    return {"ok": True, "entries_verified": len(entries), "tenant_id": tenant_id}


# ── Logging machinery ─────────────────────────────────────────────────────────

class _ChainedJSONFormatter(logging.Formatter):
    """
    Formats each log record as a single JSON line that includes cryptographic
    hash-chaining fields (prev_hash, entry_hash).

    The formatter holds a reference to the per-tenant chain state so that it
    can atomically update the running hash head under the tenant lock.
    """

    def __init__(self, tenant_id: str, chain_state: _TenantChainState) -> None:
        super().__init__()
        self._tenant_id = tenant_id
        self._chain_state = chain_state

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        entry: dict = record.msg if isinstance(record.msg, dict) else {"message": str(record.msg)}

        # Ensure timestamp is present (use existing value if caller supplied one)
        if "timestamp" not in entry:
            entry["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Ensure tenant_id is present
        if "tenant_id" not in entry:
            entry["tenant_id"] = self._tenant_id

        with self._chain_state.lock:
            prev_hash = self._chain_state.last_hash
            entry["prev_hash"] = prev_hash
            # entry_hash is computed over the entry EXCLUDING entry_hash itself
            entry_hash = _compute_entry_hash(prev_hash, entry)
            entry["entry_hash"] = entry_hash
            self._chain_state.last_hash = entry_hash

        return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ── Public API ────────────────────────────────────────────────────────────────

def get_audit_logger(tenant_id: str) -> logging.Logger:
    """
    Returns a tenant-scoped structured logger.
    Writes to logs/audit/{tenant_id}.jsonl as append-only, hash-chained JSON lines.

    Existing callers are fully compatible: pass a dict to logger.info() and it
    will be serialised with chaining fields injected automatically.
    """
    if not tenant_id:
        raise ValueError("tenant_id is required to fetch the audit logger.")

    chain_state = _get_chain_state(tenant_id)

    logger_name = f"audit.{tenant_id}"
    logger = logging.getLogger(logger_name)

    # Configure handler only once per process to avoid handler duplication.
    # We acquire the chain lock to ensure the handler is set up atomically with
    # the chain state initialisation.
    with chain_state.lock:
        if not logger.handlers:
            logger.setLevel(logging.INFO)
            base_logs_dir = os.getenv("ARGUS_LOGS_DIR", "logs")
            log_dir = Path(base_logs_dir) / "audit"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / f"{tenant_id}.jsonl"

            handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
            handler.setFormatter(_ChainedJSONFormatter(tenant_id, chain_state))
            logger.addHandler(handler)
            logger.propagate = False

    return logger


# ── Legacy-compatible re-export ───────────────────────────────────────────────
# Kept so that any code that imported JSONFormatter directly still works.
class JSONFormatter(_ChainedJSONFormatter):
    """
    Backward-compatible alias.  Callers that imported JSONFormatter from this
    module will receive a _ChainedJSONFormatter instance.  Note: without a
    tenant_id the chain state uses a sentinel 'legacy' bucket.
    """

    def __init__(self) -> None:  # type: ignore[override]
        _legacy_state = _get_chain_state("_legacy_")
        super().__init__(tenant_id="_legacy_", chain_state=_legacy_state)
